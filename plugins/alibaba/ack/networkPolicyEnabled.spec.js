var expect = require('chai').expect;
var networkPolicyEnabled = require('./networkPolicyEnabled.js');

const describeClusters = [
    {
		"name": "aqua-cluster2",
		"cluster_id": "cc377f7509590489da921de83a1cad919",
		"size": 2,
		"region_id": "us-west-1",
		"state": "initial",
		"cluster_type": "ManagedKubernetes",
		"created": "2021-06-03T19:26:32+08:00",
		"updated": "0001-01-01T00:00:00Z",
		"init_version": "v1.18.8-aliyun.1",
		"current_version": "v1.18.8-aliyun.1",
		"meta_data": "{\"Addons\":[{\"name\":\"terway-eniip\",\"version\":\"\",\"disabled\":false,\"required\":\"\",\"config\":\"{\\\"IPVlan\\\":\\\"true\\\",\\\"NetworkPolicy\\\":\\\"true\\\"}\",\"value\":\"\",\"description\":\"\",\"properties\":null},{\"name\":\"csi-plugin\",\"version\":\"\",\"disabled\":false,\"required\":\"\",\"config\":\"\",\"value\":\"\",\"description\":\"\",\"properties\":null},{\"name\":\"csi-provisioner\",\"version\":\"\",\"disabled\":false,\"required\":\"\",\"config\":\"\",\"value\":\"\",\"description\":\"\",\"properties\":null},{\"name\":\"nginx-ingress-controller\",\"version\":\"\",\"disabled\":false,\"required\":\"\",\"config\":\"{\\\"IngressSlbNetworkType\\\":\\\"internet\\\",\\\"IngressSlbSpec\\\":\\\"slb.s2.small\\\"}\",\"value\":\"\",\"description\":\"\",\"properties\":null},{\"name\":\"arms-prometheus\",\"version\":\"\",\"disabled\":false,\"required\":\"\",\"config\":\"\",\"value\":\"\",\"description\":\"\",\"properties\":null}],\"AuditProjectName\":\"\",\"Capabilities\":{\"IntelSGX\":false,\"SandboxRuntime\":true},\"CloudMonitorVersion\":\"\",\"ClusterDomain\":\"\",\"ControlPlaneLogConfig\":{\"log_ttl\":\"\",\"components\":null},\"DockerVersion\":\"\",\"EtcdVersion\":\"\",\"ExtraCertSAN\":null,\"HasSandboxRuntime\":false,\"KubernetesVersion\":\"\",\"MultiAZ\":false,\"NameMode\":\"\",\"NextVersion\":\"\",\"OSType\":\"\",\"Platform\":\"\",\"PodVswitchId\":\"{\\\"us-west-1a\\\":[\\\"vsw-rj98qqgecvwwzn5fzc62p\\\",\\\"vsw-rj94uhhrj5qz5008lwi1x\\\"]}\",\"Provider\":\"\",\"ResourceGroupId\":\"rg-aekzsj44b4lt5fa\",\"Runtime\":\"docker\",\"RuntimeVersion\":\"19.03.5\",\"SubClass\":\"\",\"SupportPlatforms\":null,\"VersionSpec\":null,\"VpcCidr\":\"172.16.0.0/12\"}",
		"resource_group_id": "rg-aekzsj44b4lt5fa",
		"instance_type": "",
		"vpc_id": "vpc-rj9vu86hdve3qr173ew17",
		"vswitch_id": "vsw-rj9755hwhio2ua0rdnm00",
		"vswitch_cidr": "",
		"data_disk_size": 0,
		"data_disk_category": "cloud",
		"security_group_id": "sg-rj95cax8rsfe92ifomz0",
		"tags": null,
		"zone_id": "us-west-1a",
		"-": "PayByTraffic",
		"network_mode": "vpc",
		"subnet_cidr": "",
		"master_url": "",
		"external_loadbalancer_id": "lb-2evcum8y76kf8a1a6s3m1",
		"port": 0,
		"node_status": "",
		"cluster_healthy": "",
		"docker_version": "",
		"swarm_mode": false,
		"gw_bridge": "",
		"upgrade_components": {
			"Kubernetes": {
				"component_name": "Kubernetes",
				"version": "v1.18.8-aliyun.1",
				"next_version": "",
				"changed": "",
				"can_upgrade": false,
				"force": false,
				"policy": "",
				"ExtraVars": null,
				"ready_to_upgrade": "",
				"message": "",
				"exist": false,
				"category": "",
				"required": false,
				"template": "",
				"value": "",
				"description": "",
				"properties": null
			}
		},
		"next_version": "",
		"private_zone": false,
		"service_discovery_types": null,
		"private_link": false,
		"profile": "Default",
		"deletion_protection": false,
		"cluster_spec": "ack.standard",
		"maintenance_window": {
			"enable": false,
			"maintenance_time": "",
			"duration": "",
			"weekly_period": ""
		},
		"capabilities": null,
		"enabled_migration": false,
		"need_update_agent": false,
		"outputs": null,
		"parameters": null,
		"worker_ram_role_name": "",
		"maintenance_info": null
	},
    {
        "name": "aqua-cluster",
        "cluster_id": "cb3341709db3c4ea587f218d347cfdfeb",
        "size": 1,
        "region_id": "us-west-1",
        "state": "running",
        "cluster_type": "ManagedKubernetes",
        "created": "2021-06-01T17:14:53+08:00",
        "updated": "2021-06-03T18:52:54+08:00",
        "init_version": "1.20.4-aliyun.1",
        "current_version": "1.20.4-aliyun.1",
        "meta_data": "{\"Addons\":[{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"csi-plugin\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"v1.18.8.47-906bd535-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"alicloud-monitor-controller\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v1.5.7-e1d5de8a-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"cloud-controller-manager\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v1.9.3.381-gd6d0962-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"csi-provisioner\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"v1.18.8.47-906bd535-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"kube-flannel-ds\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"v0.13.0.1-466064b-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"aliyun-acr-credential-helper\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v21.04.22.0-273c079-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"flannel\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"coredns\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v1.7.0\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"managed-kube-proxy\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v1.20.4-aliyun.1\"},{\"config\":\"{\\\"IngressDashboardEnabled\\\":\\\"false\\\",\\\"sls_project_name\\\":\\\"akhtar-project\\\"}\",\"description\":\"\",\"disabled\":false,\"name\":\"logtail-ds\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"v0.16.62.0-da583e0-aliyun\"},{\"config\":\"{\\\"IngressSlbNetworkType\\\":\\\"internet\\\",\\\"IngressSlbSpec\\\":\\\"slb.s2.small\\\"}\",\"description\":\"\",\"disabled\":false,\"name\":\"nginx-ingress-controller\",\"properties\":null,\"required\":\"\",\"value\":\"\",\"version\":\"v0.44.0.1-5e842447b-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"metrics-server\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v0.3.8.5-307cf45-aliyun\"},{\"config\":\"\",\"description\":\"\",\"disabled\":false,\"name\":\"ack-scheduler\",\"properties\":null,\"required\":\"true\",\"value\":\"\",\"version\":\"v1.20.4-ack-2.0\"}],\"AuditProjectName\":\"akhtar-project4\",\"Capabilities\":{\"AnyAZ\":true,\"CSI\":true,\"CpuPolicy\":true,\"DeploymentSet\":true,\"DisableEncryption\":true,\"EncryptionKMSKeyId\":\"\",\"EnterpriseSecurityGroup\":true,\"HpcCluster\":true,\"IntelSGX\":false,\"Knative\":true,\"Network\":\"Flannel\",\"NgwPayByLcu\":true,\"NodeCIDRMask\":\"26\",\"NodeNameMode\":true,\"ProxyMode\":\"ipvs\",\"PublicSLB\":false,\"RamRoleType\":\"restricted\",\"SLSProjectName\":true,\"SandboxRuntime\":true,\"SnapshotPolicy\":true,\"Taint\":true,\"TerwayEniip\":true,\"UserData\":true},\"CloudMonitorVersion\":\"\",\"ClusterDomain\":\"\",\"ControlPlaneLogConfig\":{\"aliuid\":\"0000111122223333\",\"components\":[\"apiserver\",\"kcm\",\"scheduler\"],\"log_project\":\"akhtar-project3\",\"log_ttl\":\"30\"},\"DockerVersion\":\"19.03.15\",\"EtcdVersion\":\"v3.4.3\",\"ExtraCertSAN\":null,\"HasSandboxRuntime\":false,\"KubernetesVersion\":\"1.20.4-aliyun.1\",\"MultiAZ\":false,\"NameMode\":\"\",\"NextVersion\":\"\",\"OSType\":\"Linux\",\"Platform\":\"AliyunLinux\",\"PodVswitchId\":\"\",\"Provider\":\"\",\"ResourceGroupId\":\"rg-aekzsj44b4lt5fa\",\"Runtime\":\"containerd\",\"RuntimeVersion\":\"1.4.4\",\"SubClass\":\"default\",\"SupportPlatforms\":[\"CentOS\",\"AliyunLinux\",\"Windows\",\"WindowsCore\"],\"VersionSpec\":null,\"VpcCidr\":\"10.0.0.0/8\",\"alicloud-monitor-controllerVersion\":\"v1.5.7-e1d5de8a-aliyun\",\"aliyun-acr-credential-helperVersion\":\"v21.04.22.0-273c079-aliyun\",\"corednsVersion\":\"1.7.0\",\"csi-pluginVersion\":\"v1.18.8.47-906bd535-aliyun\",\"csi-provisionerVersion\":\"v1.18.8.47-906bd535-aliyun\",\"kube-flannel-dsVersion\":\"v0.13.0.1-466064b-aliyun\",\"logtail-dsVersion\":\"v0.16.62.0-da583e0-aliyun\",\"metrics-serverVersion\":\"v0.3.8.5-307cf45-aliyun\",\"nginx-ingress-controllerVersion\":\"v0.44.0.2-abf1c6fe4-aliyun\"}",
        "resource_group_id": "rg-aekzsj44b4lt5fa",
        "instance_type": "",
        "vpc_id": "vpc-rj9xwh22u1bfdo2wjovfs",
        "vswitch_id": "vsw-rj9bp9tgbcjqe7rayhtzh",
        "vswitch_cidr": "",
        "data_disk_size": 0,
        "data_disk_category": "cloud",
        "security_group_id": "sg-rj9fujjydj19r9chwln1",
        "tags": [
            {
                "key": "ack.aliyun.com",
                "value": "cb3341709db3c4ea587f218d347cfdfeb"
            }
        ],
        "zone_id": "us-west-1a",
        "-": "PayByTraffic",
        "network_mode": "vpc",
        "subnet_cidr": "172.25.32.0/20",
        "master_url": "{\"api_server_endpoint\":\"\",\"dashboard_endpoint\":\"\",\"intranet_api_server_endpoint\":\"https://10.0.0.167:6443\"}",
        "external_loadbalancer_id": "lb-2evc9zhl4qb3uhdehq51o",
        "port": 0,
        "node_status": "",
        "cluster_healthy": "",
        "docker_version": "19.03.15",
        "swarm_mode": false,
        "gw_bridge": "",
        "upgrade_components": null,
        "next_version": "",
        "private_zone": false,
        "service_discovery_types": null,
        "private_link": false,
        "profile": "Default",
        "deletion_protection": true,
        "cluster_spec": "ack.pro.small",
        "maintenance_window": {
            "enable": false,
            "maintenance_time": "",
            "duration": "",
            "weekly_period": ""
        },
        "capabilities": null,
        "enabled_migration": false,
        "need_update_agent": false,
        "outputs": null,
        "parameters": null,
        "worker_ram_role_name": "",
        "maintenance_info": null
    }
];

const createCache = (describeClusters, describeClustersErr) => {
    return {
        ack: {
            describeClustersV1: {
                'cn-hangzhou': {
                    data: describeClusters,
                    err: describeClustersErr
                },
            }
        }
    };
};

describe('networkPolicyEnabled', function () {
    describe('run', function () {
        it('should FAIL if Cluster does not have NetworkPolicy enabled', function (done) {
            const cache = createCache([describeClusters[1]]);
            networkPolicyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cluster does not have NetworkPolicy enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Cluster has NetworkPolicy enabled', function (done) {
            const cache = createCache([describeClusters[0]]);
            networkPolicyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cluster has NetworkPolicy enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No ACK clusters found', function (done) {
            const cache = createCache([]);
            networkPolicyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ACK clusters', function (done) {
            const cache = createCache(null, { err: 'error' });
            networkPolicyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 