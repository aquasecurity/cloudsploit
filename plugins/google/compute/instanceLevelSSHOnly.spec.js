var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceLevelSSHOnly');

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

describe('instanceLevelSSHOnly', function () {
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

        it('should fail with no block project-wide ssh keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(2);
                expect(results[4].message).to.include('Block project-wide SSH keys is disabled for the following instances');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        metadata: {
                            kind: 'compute#metadata',
                            fingerprint: 'MEjZaHWy1uk=',
                            items: [
                                { key: 'block-project-ssh-keys', value: 'FALSE' },
                                { key: 'ssh-keys',
                                    value:
                                        'superdeveloper:ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAllRS9SSExDirY9MVICQlT0s26ADwoBUEr/Va2jSgkPvej4PjrGJfXSqLdZwCPMLgxtD8XyBTSgBzaUG5blIwyG4iZjgWloVVwibY9d8ZtWFWkWt7FsKPh49gAiYyFLJGZsNcfhu+vkpYy8G/4KWRRhbXHBvqmY7ejn66T+MnBO0rn2ZjRilRGxtNEN2BXq74qpPfAXwTKpBTJMUT3zfAQDyMQYR0tzGV6+sQDxboEiMoxYks1X77xr4gSSsB1lIX4iKvxQ8W97a9v90ZJfjCDttdBuloGC8vwuW/addXED6jfvQrlGXlRb+yEecndlcukksfYlEhilxPW7E5Bmq6hQ== superdeveloper@cs-6000-devshell-vm-91d3fc22-b342-4821-a6da-f4e425b311ee'
                                }
                            ]
                        }
                    }
                ],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass with block project-wide ssh key', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.equal('Block project-wide SSH keys is enabled for all instances in the region');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        metadata: {
                            kind: 'compute#metadata',
                            fingerprint: 'MEjZaHWy1uk=',
                            items: [
                                { key: 'block-project-ssh-keys', value: 'true' },
                                { key: 'ssh-keys',
                                    value:
                                        'superdeveloper:ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAllRS9SSExDirY9MVICQlT0s26ADwoBUEr/Va2jSgkPvej4PjrGJfXSqLdZwCPMLgxtD8XyBTSgBzaUG5blIwyG4iZjgWloVVwibY9d8ZtWFWkWt7FsKPh49gAiYyFLJGZsNcfhu+vkpYy8G/4KWRRhbXHBvqmY7ejn66T+MnBO0rn2ZjRilRGxtNEN2BXq74qpPfAXwTKpBTJMUT3zfAQDyMQYR0tzGV6+sQDxboEiMoxYks1X77xr4gSSsB1lIX4iKvxQ8W97a9v90ZJfjCDttdBuloGC8vwuW/addXED6jfvQrlGXlRb+yEecndlcukksfYlEhilxPW7E5Bmq6hQ== superdeveloper@cs-6000-devshell-vm-91d3fc22-b342-4821-a6da-f4e425b311ee'
                                }
                            ]
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})