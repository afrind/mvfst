/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventHandler.h>

#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/api/QuicPacketWriter.h>
#include <quic/codec/Types.h>
#include <quic/common/EventFdQueue.h>

namespace quic {

/**
 * Aggregate send-path counters for SharedThreadedPacketWriter.
 * Thread-safe: all fields are atomics. Shared across all STPW instances
 * in a process (typically one per IO worker) via std::shared_ptr.
 */
struct SharedThreadedPacketWriterStats {
  std::atomic<uint64_t> packetsEnqueued{0};  // write() returned true
  std::atomic<uint64_t> queueFull{0};        // write() returned false (queue full)
  std::atomic<uint64_t> packetsSent{0};      // segments handed to writemGSO
  std::atomic<uint64_t> partialDropped{0};   // segments lost to partial sendmmsg
};

struct PacketEntry {
  BufPtr buf;
  size_t encodedSize{0};
  folly::SocketAddress peerAddr;
  ConnectionId connId;
};

class SharedThreadedPacketWriter;

/**
 * Per-connection adaptor. Lives in conn.packetWriter. Forwards write() calls
 * to the shared writer with the connection's connId attached.
 */
class ConnectionPacketWriter : public QuicPacketWriter {
 public:
  ConnectionPacketWriter(
      SharedThreadedPacketWriter* shared,
      ConnectionId connId);

  [[nodiscard]] quic::Expected<bool, QuicError> write(
      BufPtr&& buf,
      size_t encodedSize,
      const folly::SocketAddress& peerAddr) override;

  [[nodiscard]] quic::Expected<bool, QuicError> flush() override;

  BufQuicBatchResult getResult() const override {
    return result_;
  }

 private:
  SharedThreadedPacketWriter* shared_; // non-owning; shared_ outlives this
  ConnectionId connId_;
  BufQuicBatchResult result_;
};

/**
 * One instance per socket. All connections sharing a producer EventBase use
 * the same SharedThreadedPacketWriter. Drain runs on a caller-supplied
 * folly::EventBase (which may be shared across multiple sockets/servers).
 *
 * Requires DataPathType::ChainedMemory. See QuicServer::setDrainEventBase().
 *
 * GSO grouping (UDP_SEGMENT) is restricted to same-connection packets, so
 * connIds_ stores only one entry per mmsg slot (the chain-opener's connId)
 * rather than one per segment. Cross-connection coalescing is intentionally
 * excluded; see assembleNextBatch.
 *
 * maxMsgsBeforeYield controls drain-thread fairness: lower values yield more
 * often to other EventBase handlers at the cost of peak throughput. The
 * default of 10 is tuned for server fairness, not maximum batch efficiency.
 *
 * Thread safety:
 *  - write() / flush() / registerBlocked(): called on producer EVB thread only
 *  - drainLoop() / retryAndDrain() / drainQueue(): drain EVB thread only
 *  - closed_: atomic; set by producer, checked by drain
 */
class SharedThreadedPacketWriter {
 public:
  explicit SharedThreadedPacketWriter(
      folly::AsyncUDPSocket& sock,
      folly::EventBase* producerEvb,
      folly::EventBase* drainEvb,
      size_t queueCapacity = 4096,
      size_t maxSegmentsPerMsg = 16,
      size_t maxMsgsPerCall = 64,
      size_t maxMsgsBeforeYield = 10);

  ~SharedThreadedPacketWriter();

  // Producer EVB thread. Returns false if queue is full (backpressure).
  [[nodiscard]] bool write(
      BufPtr&& buf,
      size_t encodedSize,
      const folly::SocketAddress& peerAddr,
      const ConnectionId& connId);

  // Producer EVB thread. Writes eventfd to wake drain thread.
  void flush();

  // Producer EVB thread. Register connId for write re-arm when queue drains.
  void registerBlocked(const ConnectionId& connId);

  // Called by QuicServer::shutdown(). After this, enqueues return false.
  void close();

  // Attach an aggregate stats object. May be called before or after start.
  // Counters are incremented atomically; safe to share across STPW instances.
  void setStats(std::shared_ptr<SharedThreadedPacketWriterStats> stats) {
    stats_ = std::move(stats);
  }

  // Set callbacks invoked on the producer EVB when errors occur or the queue
  // drains after backpressure. Both are called on the producer EVB thread.
  // onFatalError is called once per affected connection; onResumeProducer is
  // called with the full list of previously-blocked connection IDs.
  void setOnFatalError(
      std::function<void(const ConnectionId&, const QuicError&)> cb);
  void setOnResumeProducer(
      std::function<void(const std::vector<ConnectionId>&)> cb);

 private:
  void drainLoop(); // eventfd handler
  void retryAndDrain(); // EPOLLOUT handler
  void drainQueue(); // pull from queue in chunks

  // Fill bufs_, connIds_, addrs_, opts_, needsGso_ from the queue (up to
  // maxMsgsPerCall_ entries). GSO chains are assembled in a single pass.
  // Returns true if the queue ran dry (end reached before maxMsgsPerCall_).
  bool assembleNextBatch();

  // Call writemGSO with the current bufs_/addrs_/opts_/needsGso_.
  // Returns messages sent (>=0) on success.
  // Returns -1 if parked on EPOLLOUT (arrays left intact for retryAndDrain)
  //            or on fatal error (bufs_/connIds_ cleared, errors dispatched).
  ssize_t sendBatch();

  // Dispatch fatal write errors to the first n connections in connIds_.
  void dispatchErrors(size_t n, const QuicError& err);

  // Called on producer EVB thread to re-arm blocked connections.
  void resumeProducer();

  class SocketWritableHandler : public folly::EventHandler {
   public:
    SocketWritableHandler(
        SharedThreadedPacketWriter* writer,
        folly::EventBase* evb,
        int fd)
        : folly::EventHandler(evb, folly::NetworkSocket::fromFd(fd)),
          writer_(writer) {}

    void handlerReady(uint16_t /*events*/) noexcept override {
      unregisterHandler();
      writer_->retryAndDrain();
    }

   private:
    SharedThreadedPacketWriter* writer_;
  };

  // Coalesced flush: producer calls flush() per-connection, but we only write
  // to the eventfd once per EVB loop (or when pendingCount_ hits the threshold).
  // All fields are producer-EVB-thread-only; no atomics needed.
  static constexpr size_t kEagerFlushThreshold = 16;

  class FlushLoopCallback : public folly::EventBase::LoopCallback {
   public:
    explicit FlushLoopCallback(SharedThreadedPacketWriter* w) : w_(w) {}
    void runLoopCallback() noexcept override;

   private:
    SharedThreadedPacketWriter* w_;
  };

  std::atomic<bool> closed_{false};
  std::shared_ptr<SharedThreadedPacketWriterStats> stats_;
  EventFdQueue<PacketEntry> queue_;
  size_t maxSegmentsPerMsg_;
  size_t maxMsgsPerCall_;
  size_t maxMsgsBeforeYield_;

  folly::AsyncUDPSocket& sock_;
  folly::EventBase* producerEvb_;
  folly::EventBase* drainEvb_;
  std::unique_ptr<SocketWritableHandler> writableHandler_;

  // Drain-thread batch state. All preallocated to maxMsgsPerCall_.
  // bufs_ is non-empty when a send is pending (EAGAIN parked or in progress).
  // bufs_ and connIds_ are populated together by assembleNextBatch and
  // preserved across EAGAIN so retryAndDrain can resend without rebuilding.
  std::vector<BufPtr> bufs_;
  // One entry per mmsg slot: segment count (packets chained into this slot).
  // Tracked during assembleNextBatch() and used by sendBatch() for stats.
  std::vector<size_t> segCounts_;
  // One entry per mmsg slot: the chain-opener's connId. GSO chains are
  // restricted to a single connection so one connId per slot is sufficient.
  std::vector<ConnectionId> connIds_;
  std::vector<folly::SocketAddress> addrs_;
  std::vector<folly::AsyncUDPSocket::WriteOptions> opts_;
  bool needsGso_{false};

  // Producer EVB thread only:
  std::vector<ConnectionId> blockedConnIds_;
  bool pendingFlush_{false};
  size_t pendingCount_{0};
  FlushLoopCallback flushCallback_{this};

  // Written on producer thread (write()), read/cleared on drain thread
  // (drainQueue()). Must be atomic to avoid a data race: the write happens
  // after a failed enqueue (no release store), so the drain thread has no
  // happens-before guarantee without the atomic.
  std::atomic<bool> wasEverFull_{false};

  // Callbacks — set once at construction; called on producer EVB thread.
  std::function<void(const ConnectionId&, const QuicError&)> onFatalError_;
  std::function<void(const std::vector<ConnectionId>&)> onResumeProducer_;
};

} // namespace quic
