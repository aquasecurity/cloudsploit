var expect = require('chai').expect;
var cloudMonitorEnabled = require('./cloudMonitorEnabled.js');

const describeClusters = [
    {
		"name": "cluster1",
		"cluster_id": "cc377f7509590489da921de83a1cad918"
    }
];

const describeClusterDetail = [
    {
        "name": "cluster1",
        "cluster_id": "cc377f7509590489da921de83a1cad918",
        "size": 0,
        "region_id": "ap-south-1",
        "state": "running",
        "cluster_type": "ManagedKubernetes",
        "created": "2023-08-01T15:17:39+08:00",
        "updated": "2023-08-01T15:22:12+08:00",
        "vpc_id": "vpc-a2dwk93fhhhytkomfbkxm",
        "vswitch_id": "vsw-a2dv93afd4l9roozf0x1i",
        "external_loadbalancer_id": "lb-6gjewe9oi7jqhp786ydhr",
        "profile": "Default",
        "deletion_protection": false,
        "cluster_spec": "ack.standard",
        "maintenance_window": {
          "enable": false,
          "weekly_period": ""
        },
        "parameters": {
          "DisableAddons": "True",
          "DisableAutoCreateK8sWorkerRole": "False",
          "DisableAutoCreateK8sWorkerRolePolicy": "True",
          "DockerVersion": "17.06.2-ce-3",
          "ESSDeletionProtection": "True",
          "BetaVersion": "",
          "CloudMonitorFlags": "True",
          "CloudMonitorVersion": "1.3.7",
          "Eip": "False",
          "EipAddress": "",
          "EtcdVersion": "v3.5.4",
          "ExecuteVersion": "451735391",
          "HealthCheckType": "NONE",
          "IPStack": "ipv4",
          "ImageId": "aliyun_2_1903_x64_20G_alibase_20230522.vhd",
          "KubernetesVersion": "1.26.3-aliyun.1",
          "MasterSLBPrivateIP": "192.168.50.192",
          "NatGateway": "False",
          "NatGatewayId": "ngw-a2di7c1swotszom3b8ev0",
          "NatGatewayType": "Enhanced",
          "NatGatewayVswitchId": "",
          "Network": "terway-eniip",
          "NodeNameMode": "nodeip",
          "NumOfNodes": "0",
          "OSType": "Linux",
          "Password": "******",
          "PodVswitchIds": "[\"vsw-a2dv93afd4l9roozf0x1i\"]",
          "ProtectedInstances": "",
          "ProxyMode": "ipvs",
          "RemoveInstanceIds": "",
          "ResourceGroupId": "rg-aekzsj44b4lt5fa",
          "SNatEntry": "False",
          "ScaleOutToken": "4wnam5.lua8luvgmf8u63kk",
          "SecurityGroupId": "sg-a2delotxlubqa0csxcjp",
          "ServiceCIDR": "172.16.0.0/16",
          "WorkerDeletionProtection": "True",
          "WorkerDeploymentSetId": "",
          "WorkerHpcClusterId": "",
          "WorkerImageId": "aliyun_2_1903_x64_20G_alibase_20230522.vhd",
          "WorkerInstanceChargeType": "PostPaid",
          "WorkerInstanceTypes": "ecs.c5.xlarge",
          "WorkerKeyPair": "interop",
          "WorkerLoginPassword": "******",
          "WorkerPeriod": "3",
          "WorkerPeriodUnit": "Month",
          "WorkerSnapshotPolicyId": "******",
          "WorkerSystemDiskCategory": "cloud_ssd",
          "WorkerSystemDiskPerformanceLevel": null,
          "WorkerSystemDiskSize": "120",
          "WorkerVSwitchIds": "vsw-a2dv93afd4l9roozf0x1i",
          "ZoneId": ""
        },
        "worker_ram_role_name": "KubernetesWorkerRole-735af2c1-d38e-4348-a530-cff78749fd37",
    },
    {
        "name": "cluster2",
        "cluster_id": "cc377f7509590489da921de83a1cad919",
        "size": 0,
        "region_id": "ap-south-1",
        "state": "running",
        "cluster_type": "ManagedKubernetes",
        "created": "2023-08-01T15:17:39+08:00",
        "updated": "2023-08-01T15:22:12+08:00",
        "vpc_id": "vpc-a2dwk93fhhhytkomfbkxm",
        "vswitch_id": "vsw-a2dv93afd4l9roozf0x1i",
        "external_loadbalancer_id": "lb-6gjewe9oi7jqhp786ydhr",
        "profile": "Default",
        "deletion_protection": false,
        "cluster_spec": "ack.standard",
        "maintenance_window": {
          "enable": false,
          "weekly_period": ""
        },
        "parameters": {
          "DisableAddons": "True",
          "DisableAutoCreateK8sWorkerRole": "False",
          "DisableAutoCreateK8sWorkerRolePolicy": "True",
          "DockerVersion": "17.06.2-ce-3",
          "ESSDeletionProtection": "True",
          "BetaVersion": "",
          "CloudMonitorFlags": "False",
          "CloudMonitorVersion": "1.3.7",
          "Eip": "False",
          "EipAddress": "",
          "EtcdVersion": "v3.5.4",
          "ExecuteVersion": "451735391",
          "HealthCheckType": "NONE",
          "IPStack": "ipv4",
          "ImageId": "aliyun_2_1903_x64_20G_alibase_20230522.vhd",
          "KubernetesVersion": "1.26.3-aliyun.1",
          "MasterSLBPrivateIP": "192.168.50.192",
          "NatGateway": "False",
          "NatGatewayId": "ngw-a2di7c1swotszom3b8ev0",
          "NatGatewayType": "Enhanced",
          "NatGatewayVswitchId": "",
          "Network": "terway-eniip",
          "NodeNameMode": "nodeip",
          "NumOfNodes": "0",
          "OSType": "Linux",
          "Password": "******",
          "PodVswitchIds": "[\"vsw-a2dv93afd4l9roozf0x1i\"]",
          "ProtectedInstances": "",
          "ProxyMode": "ipvs",
          "RemoveInstanceIds": "",
          "ResourceGroupId": "rg-aekzsj44b4lt5fa",
          "SNatEntry": "False",
          "ScaleOutToken": "4wnam5.lua8luvgmf8u63kk",
          "SecurityGroupId": "sg-a2delotxlubqa0csxcjp",
          "ServiceCIDR": "172.16.0.0/16",
          "WorkerDeletionProtection": "True",
          "WorkerDeploymentSetId": "",
          "WorkerHpcClusterId": "",
          "WorkerImageId": "aliyun_2_1903_x64_20G_alibase_20230522.vhd",
          "WorkerInstanceChargeType": "PostPaid",
          "WorkerInstanceTypes": "ecs.c5.xlarge",
          "WorkerKeyPair": "interop",
          "WorkerLoginPassword": "******",
          "WorkerPeriod": "3",
          "WorkerPeriodUnit": "Month",
          "WorkerSnapshotPolicyId": "******",
          "WorkerSystemDiskCategory": "cloud_ssd",
          "WorkerSystemDiskPerformanceLevel": null,
          "WorkerSystemDiskSize": "120",
          "WorkerVSwitchIds": "vsw-a2dv93afd4l9roozf0x1i",
          "ZoneId": ""
        },
        "worker_ram_role_name": "KubernetesWorkerRole-735af2c1-d38e-4348-a530-cff78749fd37",
    }
]

const createCache = (describeClusters, describeClustersErr, describeClusterDetail, describeClusterDetailErr) => {
    let clusterId = (describeClusters && describeClusters.length) ? describeClusters[0].cluster_id : null;
    return {
        ack: {
            describeClustersV1: {
                'cn-hangzhou': {
                    data: describeClusters,
                    err: describeClustersErr
                },
            },
            describeClusterDetail: {
                'cn-hangzhou': {
                    [clusterId]: {
                        data: describeClusterDetail,
                        err: describeClusterDetailErr
                    }
                }
            }
        }
    }
};



describe('cloudMonitorEnabled', function () {
    describe('run', function () {
        it('should FAIL if Cluster does not have Cloud Monitor Enabled', function (done) {
            const cache = createCache(describeClusters, null, describeClusterDetail[1], null);
            cloudMonitorEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cluster does not have Cloud Monitor enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Cluster has Cloud Monitor enabled', function (done) {
            const cache = createCache(describeClusters, null ,describeClusterDetail[0], null);
            cloudMonitorEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cluster has Cloud Monitor enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if No ACK clusters found', function (done) {
            const cache = createCache([]);
            cloudMonitorEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ACK clusters', function (done) {
            const cache = createCache(null, { err: 'error' });
            cloudMonitorEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ACK clusters');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 