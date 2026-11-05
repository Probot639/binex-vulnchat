# -*- mode: ruby -*-
# Multi-machine Vagrant config for binex-vulnchat.
# `vagrant up linux` for the Linux test VM
# `vagrant up win` for the Windows test VM (needs box download first)
# `vagrant up` brings up both (win is autostart: false, so just linux).
#
# known issue: debian vagrant boxes on libvirt sometimes fail to obtain
# a DHCP lease (guest NIC doesn't come up). workaround: install the
# vagrant-libvirt plugin v0.12.2+, ensure the vagrant-libvirt network
# DHCP range starts at .2 not .1, and if it still hangs, try
# `vagrant up linux --provider=libvirt` with the qemu driver or switch
# to VirtualBox. the tests themselves run fine on the host without a VM:
#   cd tests && python3 -m pytest -v

Vagrant.configure("2") do |config|

  # ── Linux VM (auth + chat-linux) ────────────────────────────────
  config.vm.define "linux", primary: true do |linux|
    linux.vm.box = "debian/trixie64"
    linux.vm.hostname = "vulnchat-linux"

    linux.vm.synced_folder ".", "/vagrant", type: "rsync",
      rsync__exclude: [".git/", "services/auth/build/", "services/auth/keys/",
                       "services/chat-linux/build/", "services/chat/build/"]

    linux.vm.network "forwarded_port", guest: 4001, host: 4001
    linux.vm.network "forwarded_port", guest: 4002, host: 4002

    # the management NIC needs to be on the vagrant-libvirt network.
    # explicit config so DHCP works on boxes where the default setup stalls.
    linux.vm.network "private_network", ip: "192.168.121.10"

    linux.vm.provider :libvirt do |lv|
      lv.memory = 1024
      lv.cpus = 2
      lv.cpu_mode = "host-passthrough"
      lv.management_network_name = "vagrant-libvirt"
      lv.management_network_address = "192.168.121.0/24"
    end

    linux.vm.provision "shell", path: "tests/provision.sh"
  end

  # ── Windows VM (chat-win + client-win) ──────────────────────────
  config.vm.define "win", autostart: false do |win|
    win.vm.box = "peru/windows-server-2022-standard-x64-eval"
    win.vm.hostname = "vulnchat-win"
    win.vm.communicator = "winrm"
    win.winrm.timeout = 600

    win.vm.synced_folder ".", "C:/vagrant", type: "rsync",
      rsync__exclude: [".git/", "services/auth/build/", "services/auth/keys/",
                       "services/chat-linux/build/"]

    # windows chat server (darwin's port, mapped to 4003 on host)
    win.vm.network "forwarded_port", guest: 4002, host: 4003
    win.vm.network "private_network", ip: "192.168.121.11"

    win.vm.provider :libvirt do |lv|
      lv.memory = 4096
      lv.cpus = 2
      lv.cpu_mode = "host-passthrough"
      lv.management_network_name = "vagrant-libvirt"
      lv.management_network_address = "192.168.121.0/24"
    end

    win.vm.provision "shell", path: "tests/provision_win.ps1"
  end
end
