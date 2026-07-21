# ORGANIZATION

Given:
    - proxmoxHostname
    - proxmoxUsername
    - proxmoxAPIToken/password
    - ldap-config-base-dn = ResourceGroups

Method (GuaxMox LDAP):
    - Guac authenticates to LDAP and stores the sAMAccountName (UNAME)
    - When Guac searches ResourceGroups, looks for all groups a member is a part of and creates a list of tags (L1)
    - Create dict D1 mapping golden image VM Base Names to VMID
    - Create dict D2 mapping user VM Names to connections 
    - Query proxmox using getCluster(), getResources("vm") (L2)
    - For each VM in L2:
        - if VM.tags U L1 is empty:
            pass
        - elif it's a golden image:
            - Check D2 for a user VM
            - If no user VM exists, add VMID to D1 
        - elif it's a user image:
            - Check D1 for a golden image, delete entry if exists
            - Add Connection to D2 with
                - Name: VM.Name
                - Protocol: VNC 
                - Hostname: {vmid}.{node}.cybseclab.ua.edu 
                - Port: 5900 + VMID
                - Password: RandomString 
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

Method (guacamole-trigger)
    - Start: 
        - Get VMID and Node from regex match subdomain of hostname: `^(\d\+)\.(\w\+)\.`
        - Proxmox start VMID on Node (wait)
        - Proxmox set VNC password to ${password}
