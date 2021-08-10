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

        it('should FAIL if VM instance template does not have desired machine type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine instance template does not have desired machine type');
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
                            "canIpForward": false
                        },
                    }
                ],
                null
            );

            plugin.run(cache, settings, callback);
        })

        it('should PASS if VM instance template has desired machine type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Virtual Machine instance template has desired machine type');
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
                        },
                    }
                ],
                null
            );
            plugin.run(cache, settings, callback);
        })

    })
});
