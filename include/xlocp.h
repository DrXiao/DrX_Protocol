#ifndef __XLOCP_H__
#define __XLOCP_H__

/*
 * Dr.Xiao (Dr.Siao) - Learning-Oriented and Control Protocol - XLOCP (or SLOCP)
 *
 * For XLOCP, it defines a new protocol for the application layer of TCP/IP
 * Protocol.
 *
 * The user utilizing XLOCP must obey the following rules.
 *
 * 1.   For the original data, it needs to add a header, which is
 *      a new type of header and defined by XLOCP.
 *
 * 2.   After adding XLOCP header, user has to use...
 *
 *      A. 'TCP' protocol at tansport layer. (Adding TCP header.)
 *      B. 'IP' protocol at network layer. (IP header.)
 *      C. 'Ethernet II' at link layer. (Ethernet II Frame.)
 *
 *      Because XLOCP is at experiment phase, Obeying the above rules is in
 *      order to simply the problems while sending packets.
 * 
 *      Actually, user has to deal with more details at every layer and the details will
 *      be mentioned after.
 * 
 * 3.   XLOCP - Header structure.
 * 
 *  0         8         16         24        31 (bit)
 *  |--------------------|--------------------|
 *  |       Hash Destination IP Address       |
 *  |--------------------|--------------------|
 *  |            4 Byte Hash Code             |
 *  |--------------------|--------------------|
 *  | DataType|HdrLength |    Header Length   |
 *  |--------------------|--------------------|
 *  |     Data Length    |   Padding Length   |
 *  |--------------------|--------------------|
 *  |                Data (hash) ...          |
 *  |--------------------|--------------------|
 *  |                   ...                   |
 *  |--------------------|--------------------|
 *  |                (Padding)                |
 *  |--------------------|--------------------|
 *
 * */
#endif