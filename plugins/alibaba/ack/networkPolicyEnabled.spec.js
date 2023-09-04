var expect = require('chai').expect;
var networkPolicyEnabled = require('./networkPolicyEnabled.js');

const describeClusters = [
    {
		"name": "aqua-cluster2",
		"cluster_id": "cc377f7509590489da921de83a1cad918",
		"size": 2,
		"region_id": "us-west-1",
		"state": "initial",
		"cluster_type": "ManagedKubernetes",
		"created": "2021-06-03T19:26:32+08:00",
		"updated": "0001-01-01T00:00:00Z",
		"init_version": "v1.18.8-aliyun.1",
		"current_version": "v1.18.8-aliyun.1",
       "meta_data": "{\"Addons\":[{\"name\":\"cloud-controller-manager\",\"version\":\"v2.7.0-mgk\"}],\"AuditProjectName\":\"k8s-log-c7b90baff792e40558a01e6c0a536e1d3\",\"Capabilities\":{\"AnyAZ\":true,\"CSI\":true,\"CpuPolicy\":true,\"DeploymentSet\":true,\"DisableEncryption\":true,\"EncryptionKMSKeyId\":\"\",\"EnterpriseSecurityGroup\":true,\"HpcCluster\":true,\"IntelSGX\":false,\"Knative\":true,\"Network\":\"Flannel\",\"NgwPayByLcu\":true,\"NodeCIDRMask\":\"25\",\"NodeNameMode\":true,\"ProxyMode\":\"ipvs\",\"PublicSLB\":false,\"RamRoleType\":\"restricted\",\"SLSProjectName\":true,\"SandboxRuntime\":true,\"SnapshotPolicy\":true,\"Taint\":true,\"TerwayEniip\":true,\"UserData\":true},\"CloudMonitorVersion\":\"\",\"ClusterDomain\":\"\",\"ControlPlaneLogConfig\":{\"components\":null},\"DockerVersion\":\"\",\"EtcdVersion\":\"v3.5.4\",\"ExtraCertSAN\":null,\"HasSandboxRuntime\":false,\"IPStack\":\"ipv4\",\"ImageType\":\"AliyunLinux\",\"KubernetesVersion\":\"1.26.3-aliyun.1\",\"MultiAZ\":false,\"NameMode\":\"\",\"NextVersion\":\"\",\"OSType\":\"Linux\",\"Platform\":\"AliyunLinux\",\"PodVswitchId\":\"{\\\"ap-south-1a\\\":[\\\"vsw-a2dv93afd4l9roozf0x1i\\\"]}\",\"Provider\":\"\",\"RRSAConfig\":{\"enabled\":false},\"ResourceGroupId\":\"rg-aekzsj44b4lt5fa\",\"Runtime\":\"containerd\",\"RuntimeVersion\":\"1.6.20\",\"ServiceCIDR\":\"172.16.0.0/16\",\"SubClass\":\"default\",\"SupportPlatforms\":[\"CentOS\",\"AliyunLinux\",\"Windows\",\"WindowsCore\"],\"Timezone\":\"\",\"VSwitchIds\":null,\"VersionSpec\":null,\"VpcCidr\":\"192.168.0.0/16\",\"ack-node-local-dnsVersion\":\"1.5.6\",\"ack-node-problem-detectorVersion\":\"1.2.16\",\"alicloud-monitor-controllerVersion\":\"v1.8.3\",\"arms-prometheusVersion\":\"1.1.17\",\"cloud-controller-managerVersion\":\"v2.7.0\",\"corednsVersion\":\"v1.9.3.10-7dfca203-aliyun\",\"csi-pluginVersion\":\"v1.26.2-9d15537-aliyun\",\"csi-provisionerVersion\":\"v1.26.2-9d15537-aliyun\",\"gateway-apiVersion\":\"0.6.0\",\"logtail-dsVersion\":\"v1.5.1.0-aliyun\",\"metrics-serverVersion\":\"v0.3.9.4-ff225cd-aliyun\",\"nginx-ingress-controllerVersion\":\"v1.8.0-aliyun.1\",\"security-inspectorVersion\":\"v0.10.1.2-g13c9de7-aliyun\",\"storage-operatorVersion\":\"v1.26.1-50a1499-aliyun\",\"terway-eniipVersion\":\"v1.5.5\"}",
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
       "meta_data": "{\"Addons\":[{\"name\":\"cloud-controller-manager\",\"version\":\"v2.7.0-mgk\"}],\"AuditProjectName\":\"k8s-log-c7b90baff792e40558a01e6c0a536e1d3\",\"Capabilities\":{\"AnyAZ\":true,\"CSI\":true,\"CpuPolicy\":true,\"DeploymentSet\":true,\"DisableEncryption\":true,\"EncryptionKMSKeyId\":\"\",\"EnterpriseSecurityGroup\":true,\"HpcCluster\":true,\"IntelSGX\":false,\"Knative\":true,\"Network\":\"terway-eniip\",\"NgwPayByLcu\":true,\"NodeCIDRMask\":\"25\",\"NodeNameMode\":true,\"ProxyMode\":\"ipvs\",\"PublicSLB\":false,\"RamRoleType\":\"restricted\",\"SLSProjectName\":true,\"SandboxRuntime\":true,\"SnapshotPolicy\":true,\"Taint\":true,\"TerwayEniip\":true,\"UserData\":true},\"CloudMonitorVersion\":\"\",\"ClusterDomain\":\"\",\"ControlPlaneLogConfig\":{\"components\":null},\"DockerVersion\":\"\",\"EtcdVersion\":\"v3.5.4\",\"ExtraCertSAN\":null,\"HasSandboxRuntime\":false,\"IPStack\":\"ipv4\",\"ImageType\":\"AliyunLinux\",\"KubernetesVersion\":\"1.26.3-aliyun.1\",\"MultiAZ\":false,\"NameMode\":\"\",\"NextVersion\":\"\",\"OSType\":\"Linux\",\"Platform\":\"AliyunLinux\",\"PodVswitchId\":\"{\\\"ap-south-1a\\\":[\\\"vsw-a2dv93afd4l9roozf0x1i\\\"]}\",\"Provider\":\"\",\"RRSAConfig\":{\"enabled\":false},\"ResourceGroupId\":\"rg-aekzsj44b4lt5fa\",\"Runtime\":\"containerd\",\"RuntimeVersion\":\"1.6.20\",\"ServiceCIDR\":\"172.16.0.0/16\",\"SubClass\":\"default\",\"SupportPlatforms\":[\"CentOS\",\"AliyunLinux\",\"Windows\",\"WindowsCore\"],\"Timezone\":\"\",\"VSwitchIds\":null,\"VersionSpec\":null,\"VpcCidr\":\"192.168.0.0/16\",\"ack-node-local-dnsVersion\":\"1.5.6\",\"ack-node-problem-detectorVersion\":\"1.2.16\",\"alicloud-monitor-controllerVersion\":\"v1.8.3\",\"arms-prometheusVersion\":\"1.1.17\",\"cloud-controller-managerVersion\":\"v2.7.0\",\"corednsVersion\":\"v1.9.3.10-7dfca203-aliyun\",\"csi-pluginVersion\":\"v1.26.2-9d15537-aliyun\",\"csi-provisionerVersion\":\"v1.26.2-9d15537-aliyun\",\"gateway-apiVersion\":\"0.6.0\",\"logtail-dsVersion\":\"v1.5.1.0-aliyun\",\"metrics-serverVersion\":\"v0.3.9.4-ff225cd-aliyun\",\"nginx-ingress-controllerVersion\":\"v1.8.0-aliyun.1\",\"security-inspectorVersion\":\"v0.10.1.2-g13c9de7-aliyun\",\"storage-operatorVersion\":\"v1.26.1-50a1499-aliyun\",\"terway-eniipVersion\":\"v1.5.5\"}",
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
            const cache = createCache([describeClusters[0]]);
            networkPolicyEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cluster does not have NetworkPolicy enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Cluster has NetworkPolicy enabled', function (done) {
            const cache = createCache([describeClusters[1]]);
            networkPolicyEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cluster has NetworkPolicy enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No ACK clusters found', function (done) {
            const cache = createCache([]);
            networkPolicyEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ACK clusters', function (done) {
            const cache = createCache(null, { err: 'error' });
            networkPolicyEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 