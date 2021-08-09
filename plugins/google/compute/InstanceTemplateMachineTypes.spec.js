var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceTemplateMachineTypes');

const createCache = (instanceData, error) => {
    return {
        instanceTemplates: {
                list: {
                    'global': {
                        data: instanceData,
                        err: error
                    }
                }
        },
        projects: {
            get: {
                'global': {
                    data: 'tets-proj'
                }
            }
        }
    }
};

describe('instanceTemplateMachineTypes', function () {
    describe('run', function () {
        const settings = { instance_template_machine_types: 'e2-micro' };
        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instance templates');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, settings, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instance templates found');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, settings, callback);
        });

        it('should FAIL if VM instance is not of the desired machine type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Google Cloud Virtual Machine instance template does not have the desired machine type');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "864700679362969633",
                        "creationTimestamp": "2021-06-25T04:32:30.481-07:00",
                        "name": "instance-template-1",
                        "description": "",
                        "properties": {
                            "machineType": "e2-small",
                            "canIpForward": false,
                            "networkInterfaces": [
                                {
                                    "network": "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/networks/default",
                                    "name": "nic0",
                                    "accessConfigs": [
                                        {
                                            "type": "ONE_TO_ONE_NAT",
                                            "name": "External NAT",
                                            "networkTier": "PREMIUM",
                                            "kind": "compute#accessConfig"
                                        }
                                    ],
                                    "kind": "compute#networkInterface"
                                }
                            ],
                            "disks": [
                                {
                                    "type": "PERSISTENT",
                                    "mode": "READ_WRITE",
                                    "deviceName": "instance-template-1",
                                    "index": 0,
                                    "boot": true,
                                    "initializeParams": {
                                        "sourceImage": "projects/debian-cloud/global/images/debian-10-buster-v20210609",
                                        "diskSizeGb": "10",
                                        "diskType": "pd-balanced"
                                    },
                                    "autoDelete": true,
                                    "kind": "compute#attachedDisk"
                                }
                            ],
                            "metadata": {
                                "fingerprint": "8czNZABQPuc=",
                                "kind": "compute#metadata"
                            },
                            "serviceAccounts": [
                                {
                                    "email": "779980017373-compute@developer.gserviceaccount.com",
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
                            "scheduling": {
                                "onHostMaintenance": "MIGRATE",
                                "automaticRestart": true,
                                "preemptible": false
                            },
                            "reservationAffinity": {
                                "consumeReservationType": "ANY_RESERVATION"
                            },
                            "shieldedInstanceConfig": {
                                "enableSecureBoot": false,
                                "enableVtpm": false,
                                "enableIntegrityMonitoring": false
                            },
                            "confidentialInstanceConfig": {
                                "enableConfidentialCompute": false
                            }
                        },
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/instanceTemplates/instance-template-1",
                        "kind": "compute#instanceTemplate"
                    }
                ],
                null
            );

            plugin.run(cache, settings, callback);
        })

        it('should PASS if VM instance is of the desired machine type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Google Cloud Virtual Machine instance template has the desired machine type');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "864700679362969633",
                        "creationTimestamp": "2021-06-25T04:32:30.481-07:00",
                        "name": "instance-template-1",
                        "description": "",
                        "properties": {
                            "machineType": "e2-micro",
                            "canIpForward": false,
                            "networkInterfaces": [
                                {
                                    "network": "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/networks/default",
                                    "name": "nic0",
                                    "accessConfigs": [
                                        {
                                            "type": "ONE_TO_ONE_NAT",
                                            "name": "External NAT",
                                            "networkTier": "PREMIUM",
                                            "kind": "compute#accessConfig"
                                        }
                                    ],
                                    "kind": "compute#networkInterface"
                                }
                            ],
                            "disks": [
                                {
                                    "type": "PERSISTENT",
                                    "mode": "READ_WRITE",
                                    "deviceName": "instance-template-1",
                                    "index": 0,
                                    "boot": true,
                                    "initializeParams": {
                                        "sourceImage": "projects/debian-cloud/global/images/debian-10-buster-v20210609",
                                        "diskSizeGb": "10",
                                        "diskType": "pd-balanced"
                                    },
                                    "autoDelete": true,
                                    "kind": "compute#attachedDisk"
                                }
                            ],
                            "metadata": {
                                "fingerprint": "8czNZABQPuc=",
                                "kind": "compute#metadata"
                            },
                            "serviceAccounts": [
                                {
                                    "email": "779980017373-compute@developer.gserviceaccount.com",
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
                            "scheduling": {
                                "onHostMaintenance": "MIGRATE",
                                "automaticRestart": true,
                                "preemptible": false
                            },
                            "reservationAffinity": {
                                "consumeReservationType": "ANY_RESERVATION"
                            },
                            "shieldedInstanceConfig": {
                                "enableSecureBoot": false,
                                "enableVtpm": false,
                                "enableIntegrityMonitoring": false
                            },
                            "confidentialInstanceConfig": {
                                "enableConfidentialCompute": false
                            }
                        },
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/instanceTemplates/instance-template-1",
                        "kind": "compute#instanceTemplate"
                    }
                ],
                null
            );
            plugin.run(cache, settings, callback);
        })

    })
});