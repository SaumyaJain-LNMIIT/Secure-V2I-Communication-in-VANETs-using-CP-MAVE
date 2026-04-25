#!/usr/bin/env python3
"""
vansec/network/simulator.py — Enhanced VANET network simulator.

Models realistic channel behaviour:
  - Propagation delay   (distance-dependent, modelled as uniform random)
  - Transmission delay  (packet_size / bandwidth)
  - Processing delay    (node computation overhead)
  - Queuing delay       (waiting in MAC-layer queue)
  - Packet loss         (Bernoulli model with configurable rate)

All parameters are drawn from ``config.py`` defaults but can be overridden
per-instance.  Every transmission is logged for later metrics computation.
"""

from __future__ import annotations

import random
import time
import pickle
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import config

__all__ = ["NetworkSimulator", "TransmissionLog"]


@dataclass
class TransmissionLog:
    """Record of one simulated transmission."""
    sender: str
    receiver: str
    size_bits: int
    propagation_delay: float
    transmission_delay: float
    processing_delay: float
    queuing_delay: float
    total_delay: float
    packet_lost: bool
    timestamp: float = field(default_factory=time.time)


class NetworkSimulator:
    """
    Simulates VANET channel behaviour between two nodes.

    Usage
    -----
    >>> sim = NetworkSimulator(loss_rate=0.05)
    >>> data, delay, log = sim.transmit(payload, "Vehicle", "ECA")
    >>> metrics = sim.get_metrics()
    """

    def __init__(
        self,
        loss_rate: float = config.PACKET_LOSS_RATE,
        bandwidth_bps: float = config.BANDWIDTH_BPS,
        prop_delay: Tuple[float, float] = (
            config.PROPAGATION_DELAY_MIN,
            config.PROPAGATION_DELAY_MAX,
        ),
        proc_delay: Tuple[float, float] = (
            config.PROCESSING_DELAY_MIN,
            config.PROCESSING_DELAY_MAX,
        ),
        queue_delay: Tuple[float, float] = (
            config.QUEUING_DELAY_MIN,
            config.QUEUING_DELAY_MAX,
        ),
    ):
        self.loss_rate = loss_rate
        self.bandwidth_bps = bandwidth_bps
        self.prop_delay_range = prop_delay
        self.proc_delay_range = proc_delay
        self.queue_delay_range = queue_delay

        self.logs: List[TransmissionLog] = []
        self.total_sent = 0
        self.total_received = 0

    # ───────────────────────────────────────────────────
    # Core transmission
    # ───────────────────────────────────────────────────

    def transmit(
        self,
        data: Any,
        sender: str,
        receiver: str,
    ) -> Tuple[Optional[bytes], float, TransmissionLog]:
        """
        Simulate sending *data* from *sender* to *receiver*.

        Returns
        -------
        (serialized_data_or_None, total_delay, log_entry)
            ``None`` for the first element means the packet was lost.
        """
        serialized = pickle.dumps(data)
        size_bits = len(serialized) * 8

        # Compute individual delay components
        prop_d = random.uniform(*self.prop_delay_range)
        trans_d = size_bits / self.bandwidth_bps
        proc_d = random.uniform(*self.proc_delay_range)
        queue_d = random.uniform(*self.queue_delay_range)
        total_d = prop_d + trans_d + proc_d + queue_d

        self.total_sent += 1

        # Packet loss (Bernoulli)
        lost = random.random() < self.loss_rate

        if not lost:
            time.sleep(total_d)          # simulate the delay
            self.total_received += 1

        log_entry = TransmissionLog(
            sender=sender,
            receiver=receiver,
            size_bits=size_bits,
            propagation_delay=prop_d,
            transmission_delay=trans_d,
            processing_delay=proc_d,
            queuing_delay=queue_d,
            total_delay=total_d,
            packet_lost=lost,
        )
        self.logs.append(log_entry)

        return (None if lost else serialized), total_d, log_entry

    # ───────────────────────────────────────────────────
    # Aggregated metrics
    # ───────────────────────────────────────────────────

    def get_metrics(self) -> Dict[str, float]:
        """
        Compute aggregate metrics from all logged transmissions.

        Returns a dict with:
          - Average Delay (s)
          - Throughput (bps)
          - Jitter (s)
          - PDR (%)
          - Avg Propagation Delay (s)
          - Avg Transmission Delay (s)
          - Avg Processing Delay (s)
          - Avg Queuing Delay (s)
        """
        delivered = [l for l in self.logs if not l.packet_lost]

        if not delivered:
            return {
                "Average Delay (s)": 0.0,
                "Throughput (bps)": 0.0,
                "Jitter (s)": 0.0,
                "PDR (%)": 0.0,
                "Avg Propagation Delay (s)": 0.0,
                "Avg Transmission Delay (s)": 0.0,
                "Avg Processing Delay (s)": 0.0,
                "Avg Queuing Delay (s)": 0.0,
            }

        delays = [l.total_delay for l in delivered]
        total_bits = sum(l.size_bits for l in delivered)
        total_time = sum(delays) or 1.0

        avg_delay = sum(delays) / len(delays)
        throughput = total_bits / total_time

        # Jitter = mean of consecutive delay differences
        jitter = 0.0
        if len(delays) > 1:
            jitter = sum(
                abs(delays[i] - delays[i - 1]) for i in range(1, len(delays))
            ) / (len(delays) - 1)

        pdr = (self.total_received / self.total_sent * 100) if self.total_sent else 0.0

        return {
            "Average Delay (s)": round(avg_delay, 6),
            "Throughput (bps)": round(throughput, 2),
            "Jitter (s)": round(jitter, 6),
            "PDR (%)": round(pdr, 2),
            "Avg Propagation Delay (s)": round(
                sum(l.propagation_delay for l in delivered) / len(delivered), 6
            ),
            "Avg Transmission Delay (s)": round(
                sum(l.transmission_delay for l in delivered) / len(delivered), 6
            ),
            "Avg Processing Delay (s)": round(
                sum(l.processing_delay for l in delivered) / len(delivered), 6
            ),
            "Avg Queuing Delay (s)": round(
                sum(l.queuing_delay for l in delivered) / len(delivered), 6
            ),
        }

    # ───────────────────────────────────────────────────
    # State management
    # ───────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all logs and counters for a fresh experiment run."""
        self.logs.clear()
        self.total_sent = 0
        self.total_received = 0

    def __repr__(self) -> str:
        return (
            f"NetworkSimulator(loss={self.loss_rate}, bw={self.bandwidth_bps/1e6:.1f}Mbps, "
            f"sent={self.total_sent}, rcvd={self.total_received})"
        )
