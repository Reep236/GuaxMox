# ORGANIZATION

Given:
  - ldap-proxmox-hostname: Hostname of the Proxmox server for API interaction
  - ldap-proxmox-port:     Port of the Proxmox server to connect to 
  - ldap-proxmox-password: Password of Proxmox root@pam account
    - Will be converted to API token after Spice support is merged, necessary for VNC args 
  - ldap-config-base-dn: OU under which groups of the form DL-{TAG}-VMAccess lie 
  - ldap-user-attribtues = sAMAccountName 

Method (GuaxMox LDAP):
  - Guac authenticates to LDAP
  - From tokens, store LDAP_SAMACCOUNTNAME in UNAME
  - When Guac searches ResourceGroups, looks for all groups a member is a part of and creates a list of tags (L1)
  - Create dict D1 mapping golden image VM Names to PveClusterResources
  - Create dict D2 mapping user VM Names to Connections 
  - Query proxmox using getCluster(), getResources("vm") (L2)
  - For each VM in L2:
    - if VM.tags U L1 is empty:
      pass
    - elif it's a golden image:
      - Check D2 for a user VM
      - If no user VM exists, add PveClusterResources to D1 with key {UNAME}-{VM.Name}
    - elif it's a user image and UNAME in VM.Name:
      - Check D1 for a golden image, delete entry if exists
      - Add Connection to D2 with
        - Name: VM.Name
        - Protocol: VNC 
        - Hostname: {vmid}.{node}.cybseclab.ua.edu 
        - Port: 5900 + VMID
        - Password: 32 Character RandomString 
  - For each BaseName, VMID in D1:
    - Clone VMID to {UNAME}-{BaseName}
    - Get NEWVMID
    - Set vm.args("-vnc 0.0.0.0:{NEWVMID},password=on")
    - Add Connection to D2 with
      - Name: {UNAME}-{BaseName}
      - Protocol: VNC
      - Hostname: {NEWVMID}.{node}.cybseclab.ua.edu
      - Port: 5900 + NEWVMID
      - Password: RandomString
  - Return D2

Method (guacamole-trigger):
  - Start: 
    - Get Node from vmid.NODE.domain
    - Get VMID from port-5900
    - Proxmox start VMID on Node (wait)
    - Proxmox set VNC password to ${password}
  - Stop:
    - Proxmox stop VMID on Node (wait)
