var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./connectSerialPortsDisabled');

const createCache = (instanceData, instanceDatab, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    },
                    'us-central1-b': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-c': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-f': {
                        data: instanceDatab,
                        err: error
                    }
                }
            }
        }
    }
};

describe('connectSerialPortsDisabled', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(3);
                expect(results[4].message).to.include('Unable to query instances');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                ['null']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('No instances found');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if Connecting to Serial Ports is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(2);
                expect(results[4].message).to.include('Connecting to Serial Ports is enabled for the following instances');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "3086667528957202900",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": true,
                        "networkInterfaces": [
                            {
                                "kind": "compute#networkInterface",
                                "network": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/networks/default",
                                "subnetwork": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/regions/us-central1/subnetworks/default",
                                "networkIP": "10.128.0.5",
                                "name": "nic0",
                                "accessConfigs": [
                                    {
                                        "kind": "compute#accessConfig",
                                        "type": "ONE_TO_ONE_NAT",
                                        "name": "External NAT",
                                        "natIP": "35.193.110.217",
                                        "networkTier": "PREMIUM"
                                    }
                                ],
                                "fingerprint": "Wq0vYR9v5BQ="
                            }
                        ],
                        "disks": [
                            {
                                "kind": "compute#attachedDisk",
                                "type": "PERSISTENT",
                                "mode": "READ_WRITE",
                                "source": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3",
                                "deviceName": "instance-3",
                                "index": 0,
                                "boot": true,
                                "autoDelete": true,
                                "licenses": [
                                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                                ],
                                "interface": "SCSI",
                                "guestOsFeatures": [
                                    {
                                        "type": "VIRTIO_SCSI_MULTIQUEUE"
                                    }
                                ]
                            }
                        ],
                        "metadata": {
                            "kind": "compute#metadata",
                            "fingerprint": "InJCT-yXAGE=",
                            "items": [
                                {
                                    "key": "serial-port-enable",
                                    "value": "true"
                                }
                            ]
                        },
                        "serviceAccounts": [
                            {
                                "email": "293348421062-compute@developer.gserviceaccount.com",
                                "scopes": [
                                    "https://www.googleapis.com/auth/devstorage.read_only",
                                    "https://www.googleapis.com/auth/logging.write",
                                    "https://www.googleapis.com/auth/monitoring.write",
                                    "https://www.googleapis.com/auth/servicecontrol",
                                    "https://www.googleapis.com/auth/service.management.readonly",
                                    "https://www.googleapis.com/auth/trace.append"
                                ]
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-3",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": true,
                            "preemptible": false
                        },
                        "cpuPlatform": "Intel Haswell",
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "reservationAffinity": {
                            "consumeReservationType": "ANY_RESERVATION"
                        },
                        "displayDevice": {
                            "enableDisplay": false
                        }
                    }
                ],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if Connecting to Serial Ports is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.equal('Connecting to Serial Ports is disabled for all instances in the region');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "1074579276103575670",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/g1-small",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": false,
                        "networkInterfaces": [
                            {
                                "kind": "compute#networkInterface",
                                "network": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/networks/default",
                                "subnetwork": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/regions/us-central1/subnetworks/default",
                                "networkIP": "10.128.0.3",
                                "name": "nic0",
                                "accessConfigs": [
                                    {
                                        "kind": "compute#accessConfig",
                                        "type": "ONE_TO_ONE_NAT",
                                        "name": "External NAT",
                                        "natIP": "34.68.162.149",
                                        "networkTier": "PREMIUM"
                                    }
                                ],
                                "fingerprint": "zZcIeLJlyfk="
                            }
                        ],
                        "disks": [
                            {
                                "kind": "compute#attachedDisk",
                                "type": "PERSISTENT",
                                "mode": "READ_WRITE",
                                "source": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-2",
                                "deviceName": "instance-2",
                                "index": 0,
                                "boot": true,
                                "autoDelete": true,
                                "licenses": [
                                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                                ],
                                "interface": "SCSI",
                                "guestOsFeatures": [
                                    {
                                        "type": "VIRTIO_SCSI_MULTIQUEUE"
                                    }
                                ]
                            }
                        ],
                        "metadata": {
                            "kind": "compute#metadata",
                            "fingerprint": "XusztY_f8i4="
                        },
                        "serviceAccounts": [
                            {
                                "email": "293348421062-compute@developer.gserviceaccount.com",
                                "scopes": [
                                    "https://www.googleapis.com/auth/devstorage.read_only",
                                    "https://www.googleapis.com/auth/logging.write",
                                    "https://www.googleapis.com/auth/monitoring.write",
                                    "https://www.googleapis.com/auth/servicecontrol",
                                    "https://www.googleapis.com/auth/service.management.readonly",
                                    "https://www.googleapis.com/auth/trace.append"
                                ]
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": true,
                            "preemptible": false
                        },
                        "cpuPlatform": "Intel Haswell",
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "reservationAffinity": {
                            "consumeReservationType": "ANY_RESERVATION"
                        },
                        "displayDevice": {
                            "enableDisplay": false
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});