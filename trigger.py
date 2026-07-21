#! /opt/guacamole/.venv/bin/python3
from proxmoxer import ProxmoxAPI
from os   import getenv
from time import sleep
from sys  import argv

def start(proxmox, vmid, node, pswd):
    vm = proxmox.nodes(node).qemu(vmid)

    startUPID = vm.status.post('start')
    startStat = {'status':''}

    while (startStat['status'] != 'stopped'):
        startStat = proxmox.nodes(node).tasks(startUPID).status.get()
        sleep(1)
    
    monStat = vm.monitor.post(command=f'set_password vnc {pswd} -d vnc2')

    print('Start complete: ', startStat, monStat, sep='\n\t')

def stop(proxmox, vmid, node):
    stopUPID = proxmox.nodes(node).qemu(vmid).status.post('stop')
    stopStat = {'status':''}

    while (stopStat['status'] != 'stopped'):
        stopStat = proxmox.nodes(node).tasks(stopUPID).status.get()
        sleep(1)

    print('Stop complete: ', stopStat, sep='\n\t')

if __name__=='__main__':
    if len(argv) != 5:
        print(f'Usage: {argv[0]} <start/stop> <hostname> <port> <password>')
        print(len(argv), argv)
        exit(1)

    mode   = argv[1]
    vmHost = argv[2]
    vmPort = int(argv[3])
    vmPass = argv[4]

    vmid = vmPort - 5900
    vmNode = vmHost.split('.')[1]

    host = getenv('LDAP_PROXMOX_HOSTNAME')
    port = getenv('LDAP_PROXMOX_PORT')
    pswd = getenv('LDAP_PROXMOX_PASSWORD')
    proxmox = ProxmoxAPI(host, port=port, user='root@pam', password=pswd, verify_ssl=False)

    if   (mode == 'start'):
        start(proxmox, vmid, vmNode, vmPass)
    elif (mode == 'stop'):
        stop(proxmox, vmid, vmNode)
    else:
        print('Mode should be "start" or "stop," not ', mode)
        exit(1)

