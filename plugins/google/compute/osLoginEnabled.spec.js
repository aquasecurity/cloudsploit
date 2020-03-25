var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./osLoginEnabled');

const createCache = (data) => {
    return {
        projects: {
            get: {
                global: {
                    data: data
                }
            }
        }
      }
};
describe('osLoginEnabled', function () {
    describe('run', function () {
        it('should pass No projects found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No projects found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                {}
            );
            plugin.run(cache, {}, callback);
        });

        it('should pass enable-oslogin not found in project-wide metadata', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OS login is enabled by default');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "6528743092636155329",
                        "name": "lofty-advantage-242315",
                        "commonInstanceMetadata": {
                            "fingerprint": "LxEiFNg-nzo=",
                            "items": [],
                            "kind": "compute#metadata"
                        }
                    }
                ]
            );
            
            plugin.run(cache, {}, callback);
        })

        it('should fail enable-oslogin disabled in project-wide metadata', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OS login is disabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "6528743092636155329",
                        "name": "lofty-advantage-242315",
                        "commonInstanceMetadata": {
                            "fingerprint": "LxEiFNg-nzo=",
                            "items": [
                                { key: 'ss', value: '' },
                                { key: 'enable-oslogin', value: 'FALSE' }
                            ],
                            "kind": "compute#metadata"
                        }
                    }
                ]
            );
            
            plugin.run(cache, {}, callback);
        })

        it('should pass enable-oslogin enabled in project-wide metadata', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OS login is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "6528743092636155329",
                        "name": "lofty-advantage-242315",
                        "commonInstanceMetadata": {
                            "fingerprint": "LxEiFNg-nzo=",
                            "items": [
                                { key: 'enable-oslogin', value: 'TRUE' }
                            ],
                            "kind": "compute#metadata"
                        }
                    }
                ]
            );
            
            plugin.run(cache, {}, callback);
        })
    })
})