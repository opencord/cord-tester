# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  if (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil
    config.vm.synced_folder ".", "/cord-tester", mount_options: ["dmode=700,fmode=600"]
  else
    config.vm.synced_folder ".", "/cord-tester"
  end

  config.vm.define "cordtest" do |d|
    d.vm.box = "ubuntu/trusty64"
    d.vm.hostname = "cordtest"
    d.vm.network "private_network", ip: "10.100.198.202"
    d.vm.provision :shell, path: "src/test/setup/prerequisites.sh"
    d.vm.provider "virtualbox" do |v|
      v.memory = 3000
    end
  end

  config.vm.define "prod" do |d|
    d.vm.box = "ubuntu/trusty64"
    d.vm.hostname = "prod"
    d.vm.network "private_network", ip: "10.100.198.203"
    d.vm.provider "virtualbox" do |v|
      v.memory = 2048
    end
  end

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

end
