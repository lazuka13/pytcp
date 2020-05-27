# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrant multi-machine sample setup

Vagrant.configure("2") do |config|
  config.vm.define :alpha do |alpha|
    alpha.vm.box = "hashicorp/bionic64"
    alpha.vm.network :private_network, ip: "10.0.0.10"
    alpha.vm.hostname = "alpha"
  end

  config.vm.define :beta do |beta|
    beta.vm.box = "hashicorp/bionic64"
    beta.vm.network :private_network, ip: "10.0.0.11"
    beta.vm.hostname = "beta"
  end
end