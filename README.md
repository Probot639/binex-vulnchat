# Binex Vulnerable Service / Chatroom

##### Darwin Tran, Gavin McConnell, Odessa Rybski

## Description
Our service will be made up of a chat service and an authentication service. We’ll have both Linux and Windows clients that will access the chat service. When the user attempts to access the chat service, they will be redirected to the auth server (via SAML standards, or just Kerberos) and then sent back to the chat server. The authentication server will be vulnerable via the user ID and the chat service will be exploitable through “/” commands. Both cases will be vulnerable to buffer overflow attacks, but the chat service will also be vulnerable to use-after-free when message length . The authentication server will be written for Linux and will be compiled with the NX bit set (DEP). The idea is that we would dereference the static address of a libc function on the .plt.got section and use an add operation to get the address of mprotect. It shouldn’t be too hard to include the gadgets for this and to make sure that bit operations with a stack address being leaked are included as well. We will not be using stack canaries.
Client (Attacker) → Authentication Server (SAML or Kerberos) (Linux) (vulnerable 1) → User Authenticated Based Chat Room (Windows Client & Linux Client) (vulnerable 2)

## Implementation

## Vulnerabilities

## Setup
