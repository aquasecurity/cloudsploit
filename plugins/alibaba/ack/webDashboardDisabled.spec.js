var expect = require('chai').expect;
var webDashboardDisabled = require('./webDashboardDisabled.js');

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
        "master_url": "{\"api_server_endpoint\":\"\",\"dashboard_endpoint\":\"\",\"intranet_api_server_endpoint\":\"https://10.0.0.167:6443\"}",
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
        "master_url": "{\"api_server_endpoint\":\"\",\"dashboard_endpoint\":\"https://10.0.0.167:6443\",\"intranet_api_server_endpoint\":\"https://10.0.0.167:6443\"}",
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

describe('webDashboardDisabled', function () {
    describe('run', function () {
        it('should FAIL if Cluster has web dashboard enabled', function (done) {
            const cache = createCache([describeClusters[1]]);
            webDashboardDisabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Kubernetes Dashboard enabled in cluster');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Cluster does not have  web dashboard enabled', function (done) {
            const cache = createCache([describeClusters[0]]);
            webDashboardDisabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Kubernetes Dashboard not enabled in cluster');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No ACK clusters found', function (done) {
            const cache = createCache([]);
            webDashboardDisabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ACK clusters', function (done) {
            const cache = createCache(null, { err: 'error' });
            webDashboardDisabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 