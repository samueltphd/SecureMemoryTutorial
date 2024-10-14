/*
 * Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2002-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Tutorial author: Samuel Thomas, Brown University
 */


#include "mem/secmem-tutorial/secure_memory.hh"

namespace gem5::memory {

SecureMemory::SecureMemory(const SecureMemoryParams *p)
    : SimObject(*p),
      cpu_port(p->name + ".cpu_side", this),
      mem_port(p->name + ".mem_side", this),
      stats(*this)
{
}

Port&
SecureMemory::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "mem_side") {
        return mem_port;
    } else if (if_name == "cpu_side") {
        return cpu_port;
    }

    return SimObject::getPort(if_name, idx);
}

bool
SecureMemory::handleRequest(PacketPtr pkt)
{
    mem_port.sendPacket(pkt);

    return true;
}

bool
SecureMemory::handleResponse(PacketPtr pkt)
{
    cpu_port.sendPacket(pkt);

    return true;
}

bool
SecureMemory::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    if (blocked || !parent->handleRequest(pkt)) {
        need_retry = true;
        return false;
    }

    return true;
}

void
SecureMemory::CpuSidePort::sendPacket(PacketPtr pkt)
{
    blocked_packets.push_back(pkt);

    PacketPtr to_send = blocked_packets.front();
    if (sendTimingResp(to_send)) {
        blocked_packets.pop_front();

        if (blocked) {
            blocked = false;
        }

        if (need_retry) {
            sendRetryReq();
            need_retry = false;
        }
    }
}

bool
SecureMemory::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    return parent->handleResponse(pkt);
}

void
SecureMemory::MemSidePort::recvReqRetry()
{
    assert(!blocked_packets.empty());

    PacketPtr to_send = blocked_packets.front();
    if (sendTimingReq(to_send)) {
        blocked_packets.pop_front();
    }
}

void
SecureMemory::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingReq(pkt)) {
        blocked_packets.push_back(pkt);
    }
}

SecureMemory::SecureMemoryStats::SecureMemoryStats(SecureMemory &m)
    : statistics::Group(&m), m(m),
      ADD_STAT(requests_processed, statistics::units::Count::get(),
               "number of requests from the processor side that we've handled"),
      ADD_STAT(responses_processed, statistics::units::Count::get(),
               "number of memory responses that we've handled")
{
}

void
SecureMemory::SecureMemoryStats::regStats()
{
    statistics::Group::regStats();
}

}; // namespace gem5::memory

gem5::memory::SecureMemory *
gem5::SecureMemoryParams::create() const
{
    return new gem5::memory::SecureMemory(this);
}
