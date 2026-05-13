/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/SharedThreadedPacketWriter.h>

#include <cerrno>

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>

#include <folly/tracing/StaticTracepoint.h>
#include <quic/common/MvfstLogging.h>

namespace quic {

// ── ConnectionPacketWriter ──────────────────────────────────────────────────

ConnectionPacketWriter::ConnectionPacketWriter(
    SharedThreadedPacketWriter* shared,
    ConnectionId connId)
    : shared_(shared), connId_(std::move(connId)) {}

quic::Expected<bool, QuicError> ConnectionPacketWriter::write(
    BufPtr&& buf,
    size_t encodedSize,
    const folly::SocketAddress& peerAddr) {
  if (!shared_->write(std::move(buf), encodedSize, peerAddr, connId_)) {
    shared_->registerBlocked(connId_);
    return false;
  }
  result_.packetsSent++;
  result_.bytesSent += encodedSize;
  return true;
}

quic::Expected<bool, QuicError> ConnectionPacketWriter::flush() {
  shared_->flush();
  return true;
}

// ── SharedThreadedPacketWriter ──────────────────────────────────────────────

SharedThreadedPacketWriter::SharedThreadedPacketWriter(
    folly::AsyncUDPSocket& sock,
    folly::EventBase* producerEvb,
    folly::EventBase* drainEvb,
    size_t queueCapacity,
    size_t maxSegmentsPerMsg,
    size_t maxMsgsPerCall,
    size_t maxMsgsBeforeYield)
    : queue_(drainEvb, queueCapacity),
      maxSegmentsPerMsg_(maxSegmentsPerMsg),
      maxMsgsPerCall_(maxMsgsPerCall),
      maxMsgsBeforeYield_(maxMsgsBeforeYield),
      sock_(sock),
      producerEvb_(producerEvb),
      drainEvb_(drainEvb) {
  queue_.setOnReadable([this] { drainLoop(); });

  // GSO grouping (UDP_SEGMENT) is Linux-only. On other platforms, disable it so
  // writemGSO is always called with null options (gso==0 in every batch entry).
#ifndef FOLLY_HAVE_MSG_ERRQUEUE
  maxSegmentsPerMsg_ = 1;
#else
  // UDP_MAX_SEGMENTS=128 is the kernel's per-super-packet GSO segment limit.
  // Exceeding it causes silent drops after sendmsg() returns success.
  maxSegmentsPerMsg_ = std::min(maxSegmentsPerMsg_, size_t(128));
#endif

  int sockFd = sock_.getNetworkSocket().toFd();
  writableHandler_ = std::make_unique<SocketWritableHandler>(
      this, drainEvb_, sockFd);

  bufs_.reserve(maxMsgsPerCall_);
  segCounts_.resize(maxMsgsPerCall_, 0);
  connIds_.resize(maxMsgsPerCall_, ConnectionId::createZeroLength());
  addrs_.resize(maxMsgsPerCall_);
  opts_.resize(maxMsgsPerCall_);

  drainEvb_->runInEventBaseThread([this] { queue_.startConsuming(); });
}

SharedThreadedPacketWriter::~SharedThreadedPacketWriter() {
  flushCallback_.cancelLoopCallback();
  bufs_.clear();
}

bool SharedThreadedPacketWriter::write(
    BufPtr&& buf,
    size_t encodedSize,
    const folly::SocketAddress& peerAddr,
    const ConnectionId& connId) {
  if (closed_.load(std::memory_order_relaxed)) {
    return false;
  }
  MVCHECK(peerAddr.isFamilyInet()) << "bad peerAddr family="
      << peerAddr.getFamily() << " connId=" << connId.hex();
  PacketEntry entry{std::move(buf), encodedSize, peerAddr, connId};
  if (!queue_.enqueue(std::move(entry))) {
    wasEverFull_ = true;
    FOLLY_SDT(quic, shared_packet_writer_queue_full);
    if (stats_) {
      stats_->queueFull.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
  }
  FOLLY_SDT(quic, shared_packet_writer_enqueue, queue_.sizeGuess());
  if (stats_) {
    stats_->packetsEnqueued.fetch_add(1, std::memory_order_relaxed);
  }
  return true;
}

void SharedThreadedPacketWriter::flush() {
  if (++pendingCount_ >= kEagerFlushThreshold) {
    pendingCount_ = 0;
    pendingFlush_ = false;
    queue_.flush();
  } else if (!pendingFlush_) {
    // First pending packet this loop: arm the callback to flush the tail.
    pendingFlush_ = true;
    producerEvb_->runBeforeLoop(&flushCallback_);
  }
}

void SharedThreadedPacketWriter::FlushLoopCallback::runLoopCallback() noexcept {
  // pendingFlush_ is always true when we reach here (we only arm on first pending).
  w_->pendingFlush_ = false;
  w_->pendingCount_ = 0;
  w_->queue_.flush();
  // Do not re-arm; flush() will re-arm next time it has pending data.
}

void SharedThreadedPacketWriter::registerBlocked(
    const ConnectionId& connId) {
  blockedConnIds_.push_back(connId);
}

void SharedThreadedPacketWriter::setOnFatalError(
    std::function<void(const ConnectionId&, const QuicError&)> cb) {
  onFatalError_ = std::move(cb);
}

void SharedThreadedPacketWriter::setOnResumeProducer(
    std::function<void(const std::vector<ConnectionId>&)> cb) {
  onResumeProducer_ = std::move(cb);
}

void SharedThreadedPacketWriter::close() {
  closed_.store(true, std::memory_order_relaxed);
}

void SharedThreadedPacketWriter::drainLoop() {
  // If a retry is pending, don't drain — let the queue fill naturally so the
  // producer pauses. drainQueue() will be called by retryAndDrain().
  if (!bufs_.empty()) {
    return;
  }
  drainQueue();
}

void SharedThreadedPacketWriter::retryAndDrain() {
  MVDCHECK(!bufs_.empty());
  // bufs_, connIds_, addrs_, opts_, needsGso_ are still populated from the
  // failed send — call sendBatch() directly without rebuilding anything.
  // A partial send (ret < batch size) on retry is treated as loss; QUIC retransmits.
  if (sendBatch() < 0) {
    return;
  }
  drainQueue();
}

bool SharedThreadedPacketWriter::assembleNextBatch() {
  MVDCHECK(bufs_.empty()); // cleared by sendBatch on success/fatal
  // connIds_, addrs_, opts_ are sized to maxMsgsPerCall_ and may hold stale
  // data from the previous batch; overwrite from index 0 — no resize needed.
  needsGso_ = false;
  size_t n = 0; // slots written this call

  size_t prevSize = 0;
  size_t gso = 0;
  size_t segsInChain = 0; // segments in the current mmsg slot
  folly::SocketAddress curAddr;
  ConnectionId curConnId = ConnectionId::createZeroLength();
  bool hasCurrentChain = false;

  PacketEntry entry{
      nullptr, 0, folly::SocketAddress{}, ConnectionId::createZeroLength()};
  while (n < maxMsgsPerCall_ && queue_.dequeue(entry)) {
    size_t size = entry.encodedSize;
    // GSO grouping: same connection, same peer address, uniform packet
    // size, and chain not yet at the segment limit. Mixing sizes is excluded:
    // a non-uniform tail (size < prevSize) requires gso_size == all non-last
    // segments, but the canAppend path sets gso from the opener's encodedSize,
    // not from buf->computeChainDataLength() — if those ever diverge the kernel
    // splits at the wrong byte offset and corrupts all segments in the batch.
    // Cross-connection coalescing is also excluded — it's rare on servers and
    // removes the need for a vector<ConnectionId> per slot.
    bool canAppend = hasCurrentChain && size == prevSize &&
        entry.peerAddr == curAddr &&
        entry.connId == curConnId && segsInChain < maxSegmentsPerMsg_;

    if (canAppend) {
      // Append to current chain.
      bufs_.back()->appendChain(std::move(entry.buf));
      gso = prevSize; // gso is the uniform segment size
      prevSize = size;
      segsInChain++;
    } else {
      // Finalize the previous chain's gso and segment count in opts_/segCounts_.
      if (hasCurrentChain) {
        // n >= 1: hasCurrentChain is only set after the first push_back.
        opts_[n - 1] = folly::AsyncUDPSocket::WriteOptions(
            static_cast<int>(gso), /*zerocopy=*/false);
        segCounts_[n - 1] = segsInChain;
        if (gso > 0) {
          needsGso_ = true;
        }
      }
      // addrs_/opts_/connIds_ at index n are pre-allocated; bufs_ grows via push_back.
      bufs_.push_back(std::move(entry.buf));
      addrs_[n] = entry.peerAddr;
      opts_[n] = folly::AsyncUDPSocket::WriteOptions(0, false);
      connIds_[n] = entry.connId;
      n++;
      prevSize = size;
      gso = 0;
      segsInChain = 1;
      curAddr = entry.peerAddr;
      curConnId = entry.connId;
      hasCurrentChain = true;
    }
  }
  // Finalize the last chain.
  if (hasCurrentChain) {
    opts_[n - 1] = folly::AsyncUDPSocket::WriteOptions(
        static_cast<int>(gso), /*zerocopy=*/false);
    segCounts_[n - 1] = segsInChain;
    if (gso > 0) {
      needsGso_ = true;
    }
  }
  return n < maxMsgsPerCall_; // true if queue ran dry
}

ssize_t SharedThreadedPacketWriter::sendBatch() {
  size_t n = bufs_.size();
  int ret = sock_.writemGSO(
      folly::Range<folly::SocketAddress const*>(addrs_.data(), n),
      bufs_.data(),
      n,
      needsGso_ ? opts_.data() : nullptr);
  MVVLOG(3) << "writemGSO batch=" << n << " ret=" << ret;

  if (ret < 0) {
    int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS) {
      // TX buffer full. bufs_ stays intact — retryAndDrain will resend.
      writableHandler_->registerHandler(
          folly::EventHandler::WRITE | folly::EventHandler::PERSIST);
      return -1;
    }
    // Fatal error.
    auto quicErr = QuicError(
        QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED),
        std::string("SharedThreadedPacketWriter: fatal write error"));
    dispatchErrors(n, quicErr);
    bufs_.clear();
    return -1;
  }

  // Success: release IOBufs. addrs_/opts_/connIds_ stay at maxMsgsPerCall_
  // size so assembleNextBatch always has pre-initialized slots to overwrite.
  // Unsent entries (ret < n) are treated as loss; QUIC retransmits.
  FOLLY_SDT(quic, shared_packet_writer_batch_result, n, static_cast<size_t>(ret));
  if (stats_) {
    // segCounts_[i] = packets dequeued into slot i; each becomes one UDP
    // datagram (or N datagrams via kernel GSO splitting for GSO slots).
    size_t segs = 0;
    for (size_t i = 0; i < static_cast<size_t>(ret); i++) {
      segs += segCounts_[i];
    }
    stats_->packetsSent.fetch_add(segs, std::memory_order_relaxed);
    if (static_cast<size_t>(ret) < n) {
      FOLLY_SDT(quic, shared_packet_writer_partial_send, n, ret);
      size_t dropped = 0;
      for (size_t i = static_cast<size_t>(ret); i < n; i++) {
        dropped += segCounts_[i];
      }
      stats_->partialDropped.fetch_add(dropped, std::memory_order_relaxed);
    }
  }
  bufs_.clear();
  return static_cast<ssize_t>(ret); // message count, not bytes
}

void SharedThreadedPacketWriter::drainQueue() {
  MVVLOG(3) << "drainQueue";
  size_t totalMsgsSent = 0;

  while (true) {
    bool hitEnd = assembleNextBatch();

    // Low-water mark: re-arm producers when the queue runs dry. We only load
    // wasEverFull_ on hitEnd to avoid the atomic read on every iteration.
    if (hitEnd && wasEverFull_.load(std::memory_order_relaxed)) {
      wasEverFull_.store(false, std::memory_order_relaxed);
      producerEvb_->runInEventBaseThread([this] { resumeProducer(); });
    }

    if (bufs_.empty()) {
      // hitEnd=true and queue was already empty; nothing to send.
      FOLLY_SDT(quic, shared_packet_writer_drain_done, totalMsgsSent);
      return;
    }

    ssize_t sent = sendBatch();
    if (sent < 0) {
      return; // parked on EPOLLOUT or fatal
    }
    totalMsgsSent += static_cast<size_t>(sent);

    if (totalMsgsSent >= maxMsgsBeforeYield_) {
      // Yield to other handlers. If the queue was empty when we last assembled,
      // there's nothing left to drain — skip the wakeup. Any packets the
      // producer adds after this point will fire the eventfd via flush().
      FOLLY_SDT(
          quic,
          shared_packet_writer_yield,
          totalMsgsSent,
          hitEnd ? 0 : 1 /*rescheduled*/);
      if (!hitEnd) {
        // Use drainLoop (not drainQueue) so the bufs_.empty() guard fires if
        // a concurrent EAGAIN left bufs_ non-empty before this callback runs.
        drainEvb_->runInEventBaseThread([this] { drainLoop(); });
      }
      return;
    }
  }
}

void SharedThreadedPacketWriter::dispatchErrors(size_t n, const QuicError& err) {
  if (!onFatalError_) {
    return;
  }
  auto cb = onFatalError_;
  for (size_t i = 0; i < n; i++) {
    producerEvb_->runInEventBaseThread([cb, connId = connIds_[i], err]() {
      cb(connId, err);
    });
  }
}

void SharedThreadedPacketWriter::resumeProducer() {
  // Called on producer EVB thread. Re-arm all connections that blocked because
  // the queue was full. wasEverFull_ was already cleared by the drain thread
  // before this callback was scheduled.
  if (onResumeProducer_ && !blockedConnIds_.empty()) {
    onResumeProducer_(blockedConnIds_);
  }
  blockedConnIds_.clear();
}

} // namespace quic
