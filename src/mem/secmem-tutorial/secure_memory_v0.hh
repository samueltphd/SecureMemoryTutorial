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


#ifndef __MEM_SECURE_MEMORY__
#define __MEM_SECURE_MEMORY__


#include "base/statistics.hh"
#include "mem/port.hh"
#include "params/SecureMemory.hh"
#include "sim/sim_object.hh"

namespace gem5::memory {

class SecureMemory : public SimObject
{
    // declare the ports so that we can have them call the class functions to
    // handle requests/responses
  private:
    // note: there are also queued ports, we will implement this naively
    class CpuSidePort : public ResponsePort
    {
      private:
        SecureMemory *parent;
        // we can decide if we want to block
        bool blocked;
        // if we receive a request while blocked, we need to notify the
        // the requestor when we unblock
        bool need_retry;

        // to store state from responses that we cannot send to the requestor
        // yet because they are blocked
        std::list<PacketPtr> blocked_packets;

      public:
        CpuSidePort(const std::string &name, SecureMemory *parent)
            : ResponsePort(name),
              parent(parent),
              blocked(false),
              need_retry(false)
        {  };

      protected:
        ////  Packet functions  ////

        // for fast-forwarding
        Tick recvAtomic(PacketPtr pkt) override {
            return parent->mem_port.sendAtomic(pkt);
        };

        // for restoring from checkpoints
        void recvFunctional(PacketPtr pkt) override {
            parent->mem_port.sendFunctional(pkt);
        };

        // for timing (normal case)
        bool recvTimingReq(PacketPtr pkt) override; // defined in source file

        void recvRespRetry() override {  };

        ////  auxiliary functions  ////

        // allow the base class to block incoming requests
        void setBlocked() { blocked = true; }

        // for gem5 on construction, get addr ranges from memory side
        AddrRangeList getAddrRanges() const override {
            return parent->mem_port.getAddrRanges();
        }

      public:
        // wrapper for sendTimingResp that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source file
    };

    // note: there are also queued ports, we will implement this naively
    class MemSidePort : public RequestPort
    {
      private:
        SecureMemory *parent;

        // to store state for requests that we cannot send to the memory device
        // is currently blocked (bandwidth saturated)
        std::list<PacketPtr> blocked_packets;

      public:
        MemSidePort(const std::string &name,
                    SecureMemory *parent)
            : RequestPort(name),
              parent(parent)
        {  };

        bool isSnooping() const override { return false; }

      protected:
        ////  packet functions  ////

        // note, atomic and functional requests do not have responses
        // for timing (normal case)
        bool recvTimingResp(PacketPtr pkt) override; // defined in source file
        // when we were blocked by a memory device, it will notify us here
        // if it unblocks
        void recvReqRetry() override; // defined in source file

        ////  auxiliary functions  ////

        // this is a weird gem5-feature, but let's just forward the range to
        // the cpu side
        void recvRangeChange() override {
            parent->cpu_port.sendRangeChange();
        };

      public:
        // wrapper for sendTimingReq that handles blocking
        void sendPacket(PacketPtr pkt); // defined in source file
    };

    CpuSidePort cpu_port;
    MemSidePort mem_port;

    bool handleRequest(PacketPtr pkt); // we will do our work here
    bool handleResponse(PacketPtr pkt); // and here

  public:
    SecureMemory(const SecureMemoryParams *p);

    // this is important for connecting front-end to back-end
    Port &getPort(const std::string &if_name,
                  PortID idx=InvalidPortID) override;

    // for stats
    struct SecureMemoryStats : public statistics::Group
    {
        SecureMemoryStats(SecureMemory &m);
        void regStats() override;

        const SecureMemory &m;

        statistics::Scalar requests_processed;
        statistics::Scalar responses_processed;
    };

    SecureMemoryStats stats;
};

}; // gem5::memory


#endif // __MEM_SECURE_MEMORY__
