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

if node.cassandra.opscenter.agent.from_server
  server_ip = nil
  if not Chef::Config.solo
    search(:node, "role:cassandra AND chef_environment:#{node.chef_environment}").each do |n|
      server_ip = n[:ec2][:local_ipv4]
      break
    end
  end
  remote_file "/tmp/opscenter-agent.deb" do
    source "http://#{server_ip}/opscenter-agent.deb"
  end
else
  package "#{node[:cassandra][:opscenter][:agent][:package_name]}" do
    action :install
    version node.cassandra.opscenter.agent.version
  end
end

service "datastax-agent" do
  supports :restart => true, :status => true
  action [:enable, :start]
end


template "/etc/datastax-agent/address.yaml" do
  mode 0644
  source "opscenter-agent.conf.erb"
  variables({
    :server_ip => server_ip
  })
  notifies :restart, "service[datastax-agent]"
end
