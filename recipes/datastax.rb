#
# Cookbook Name:: cassandra
# Recipe:: datastax
#
# Copyright 2011-2012, Michael S Klishin & Travis CI Development Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

node.default[:cassandra][:installation_dir] = "/usr/share/cassandra"
# node.cassandra.installation_dir subdirs
node.default[:cassandra][:bin_dir]   = File.join(node.cassandra.installation_dir, 'bin')
node.default[:cassandra][:lib_dir]   = File.join(node.cassandra.installation_dir, 'lib')

#node.default[:cassandra][:conf_dir]  = "/etc/cassandra/conf"

# commit log, data directory, saved caches and so on are all stored under the data root. MK.
# node.cassandra.root_dir sub dirs
node.default[:cassandra][:data_dir] = File.join(node.cassandra.root_dir, 'data')
node.default[:cassandra][:commitlog_dir] = File.join(node.cassandra.root_dir, 'commitlog')
node.default[:cassandra][:saved_caches_dir] = File.join(node.cassandra.root_dir, 'saved_caches')

include_recipe "java"

Chef::Application.fatal!("attribute node['cassandra']['cluster_name'] not defined") unless node.cassandra.cluster_name

include_recipe "cassandra::user" if node.cassandra.setup_user

case node["platform_family"]
when "debian"
  node.default[:cassandra][:conf_dir]  = "/etc/cassandra"
  # I don't understand why these are needed when installing from a package? Certainly broken on Centos. 
=begin
  [node.cassandra.installation_dir,
   node.cassandra.bin_dir,
   node.cassandra.lib_dir].each do |dir|

     directory dir do
       owner     node.cassandra.user
       group     node.cassandra.group
       recursive true
       action    :create
     end
   end
=end

  if node['cassandra']['dse']
    dse = node.cassandra.dse
    if dse.credentials.databag
      dse_credentials = Chef::EncryptedDataBagItem.load(dse.credentials.databag.name, dse.credentials.databag.item)[dse.credentials.databag.entry]
    else
      dse_credentials = dse.credentials
    end

    package "apt-transport-https"

    apt_repository "datastax" do
      uri          "http://#{dse_credentials['username']}:#{dse_credentials['password']}@debian.datastax.com/enterprise"
      distribution "stable"
      components   ["main"]
      key          "http://debian.datastax.com/debian/repo_key"
      action :add
    end
  else
    apt_repository "datastax" do
      uri          "http://debian.datastax.com/community"
      distribution "stable"
      components   ["main"]
      key          "http://debian.datastax.com/debian/repo_key"

      action :add
    end

    # DataStax Server Community Edition package will not install w/o this
    # one installed. MK.
    package "python-cql" do
      action :install
    end
  end

  # If you're installing the Enterprise package (as opposed to Community
  # edition), and it's not the latest version, you have to install the proper
  # version of each dependency. This Bash script recursively grabs all of the
  # dependencies and installs them in one fell swoop.
  if node[:cassandra][:package_name] == 'dse-full'
    node.normal.cassandra.conf_dir = '/etc/dse/cassandra'
    bash "dse-package-install" do
      code <<-EOF
        set -o nounset
        set -o errexit
        set -o pipefail

        dse_package=#{node[:cassandra][:package_name]}
        dse_version=#{node[:cassandra][:version]}
    
        function get_dse_deps {
          package=$1; shift
          version=$1; shift
          # Get the dependencies. Ignore non-zero return codes.
          dependencies=$(apt-cache depends ${package}=${version} | grep 'Depends: dse' | awk '{ print $2 }' || true)
          echo "${package}"
          for dependency in ${dependencies}; do
            get_dse_deps ${dependency} ${version};
          done
        }
        export DEBIAN_FRONTEND=noninteractive
        get_dse_deps "${dse_package}" "${dse_version}" | sort | uniq | sed "s/$/=${dse_version}/" | xargs apt-get --force-yes install -y -o Dpkg::Options::="--force-confold"
      EOF
      not_if ("dpkg -s #{node.cassandra.package_name} | grep '^Version: #{node.cassandra.version}'")

    end
  else
    package "#{node.cassandra.package_name}" do
      action :install
      version node.cassandra.version
    end
  end
  apt_preference "#{node.cassandra.package_name}" do
    pin "version #{node.cassandra.version}"
    pin_priority "700"
  end

when "rhel"
  node.default[:cassandra][:conf_dir]  = "/etc/cassandra/conf"
  include_recipe "yum"

  if node['cassandra']['dse']
    dse = node.cassandra.dse
    if dse.credentials.databag
      dse_credentials = Chef::EncryptedDataBagItem.load(dse.credentials.databag.name, dse.credentials.databag.item)[dse.credentials.databag.entry]
    else
      dse_credentials = dse.credentials
    end

    yum_repository "datastax" do
      description "DataStax Repo for Apache Cassandra"
      baseurl     "http://#{dse_credentials['username']}:#{dse_credentials['password']}@rpm.datastax.com/enterprise"
      gpgcheck    false
      action      :create
    end

  else
    yum_repository "datastax" do
      description   "DataStax Repo for Apache Cassandra"
      baseurl       "http://rpm.datastax.com/community"
      gpgcheck      false
      action        :create
    end
  end

  yum_package "#{node.cassandra.package_name}" do
    version "#{node.cassandra.version}-#{node.cassandra.release}"
    allow_downgrade
  end

  # Ignoring /etc/cassandra/conf completely and using /usr/share/cassandra/conf

  link node.cassandra.conf_dir do
    to        File.join(node.cassandra.installation_dir, 'default.conf')
    owner     node.cassandra.user
    group     node.cassandra.group
    action    :create
  end
end

# These are required irrespective of package construction. 
# node.cassandra.root_dir sub dirs need not to be managed by Chef, 
# C* service creates sub dirs with right user perm set.
# Disabling, will keep entries till next commit.
#
[node.cassandra.installation_dir,
  node.cassandra.bin_dir,
  node.cassandra.log_dir,
  node.cassandra.root_dir,
  node.cassandra.lib_dir].each do |dir|
  directory dir do
    owner     node.cassandra.user
    group     node.cassandra.group
    recursive true
    mode      0755
    action    :create
  end
end

%w(cassandra.yaml cassandra-env.sh log4j-server.properties).each do |f|
  template File.join(node.cassandra.conf_dir, f) do
    cookbook node.cassandra.templates_cookbook
    source "#{f}.erb"
    owner node.cassandra.user
    group node.cassandra.group
    mode  "0644"
    notifies :restart, "service[cassandra]", :delayed if node.cassandra.notify_restart
  end
end

if node.cassandra.attribute?("rackdc")
  template File.join(node.cassandra.conf_dir, "cassandra-rackdc.properties") do
    source "cassandra-rackdc.properties.erb"
    owner node.cassandra.user
    group node.cassandra.group
    mode  0644
    variables ({ :rackdc => node.cassandra.rackdc })
    notifies :restart, "service[cassandra]", :delayed if node.cassandra.notify_restart
  end
end

[File.join(node.cassandra.log_dir, 'system.log'), File.join(node.cassandra.log_dir, 'boot.log')].each {|f|
  file f do
    owner node.cassandra.user
    group node.cassandra.group
    mode  "0644"
    action :create
  end
}

if node.cassandra.setup_jna
  remote_file "/usr/share/java/jna.jar" do
    source "#{node.cassandra.jna.base_url}/#{node.cassandra.jna.jar_name}"
    checksum node.cassandra.jna.sha256sum
  end

  link "#{node.cassandra.lib_dir}/jna.jar" do
    to          "/usr/share/java/jna.jar"
    notifies :restart, "service[cassandra]", :delayed if node.cassandra.notify_restart
  end
end

service "cassandra" do
  supports :restart => true, :status => true
  service_name node.cassandra.service_name
  action node.cassandra.service_action
end
