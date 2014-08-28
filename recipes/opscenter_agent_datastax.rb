#
# Cookbook Name:: cassandra
# Recipe:: opscenter_agent_datastax
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

include_recipe "java"

case node["platform_family"]
when "debian"

  if node['cassandra']['dse']
    dse = node['cassandra']['dse']
    if dse['credentials']['databag']
      dse_credentials = Chef::EncryptedDataBagItem.load(dse['credentials']['databag']['name'], dse['credentials']['databag']['item'])[dse['credentials']['databag']['entry']]
    else
      dse_credentials = dse['credentials']
    end
    apt_repository "datastax" do
      uri          "http://#{dse_credentials['username']}:#{dse_credentials['password']}@debian.datastax.com/enterprise"
      distribution "stable"
      components   ["main"]
      key          "https://debian.datastax.com/debian/repo_key"
      action :add
    end
  else
    apt_repository "datastax" do
      uri          "https://debian.datastax.com/community"
      distribution "stable"
      components   ["main"]
      key          "https://debian.datastax.com/debian/repo_key"
      action :add
    end
  end

when "rhel"
  include_recipe "yum"

  yum_repository "datastax" do
    description "DataStax Repo for Apache Cassandra"
    baseurl "http://rpm.datastax.com/community"
    gpgcheck false
    action :create
  end
end

server_ip = node[:cassandra][:opscenter][:agent][:server_host]
if !server_ip
  search_results = search(:node, "roles:#{node[:cassandra][:opscenter][:agent][:server_role]}")
  unless search_results.empty?
    server_ip = search_results[0]['ipaddress']
  else
    return # Continue until opscenter will come up
  end
end 

address_file = "/etc/#{node.cassandra.opscenter.agent.package_name}/address.yaml"

if node.cassandra.opscenter.agent.from_server
  deb_file = "#{node.cassandra.opscenter.agent.package_name}.deb"
  remote_file "/tmp/#{deb_file}" do
    source "http://#{server_ip}/opscenter-agent/#{deb_file}"
  end
  dpkg_package node.cassandra.opscenter.agent.package_name do
    source "/tmp/#{deb_file}"
    action :install
  end
  file "/tmp/#{deb_file}" do
    action :delete
  end
  ['conf', 'ssl'].each do |dir|
    directory "/var/lib/#{node.cassandra.opscenter.agent.package_name}/#{dir}" do
      owner node.cassandra.opscenter.agent.owner
      group node.cassandra.opscenter.agent.group
      mode 0755
      action :create
    end
  end
  remote_file "/var/lib/#{node.cassandra.opscenter.agent.package_name}/ssl/agentKeyStore" do
    source "http://#{server_ip}/opscenter-agent/ssl/agentKeyStore"
  end
else
  package node.cassandra.opscenter.agent.package_name do
    action :install
    version node.cassandra.opscenter.agent.version
  end
end

service node.cassandra.opscenter.agent.service_name do
  supports :restart => true, :status => true
  action [:enable, :start]
end

template "#{address_file}" do
  mode 0644
  owner node.cassandra.opscenter.agent.owner
  group node.cassandra.opscenter.agent.group
  source "opscenter-agent.conf.erb"
  variables({
    :server_ip => server_ip
  })
  notifies :restart, "service[#{node.cassandra.opscenter.agent.service_name}]"
end
