var expect = require('chai').expect;
var plugin = require('./imagesCMKEncrypted');

const cryptoKeys = [
    {
        name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2/cryptoKeyVersions/1",
            state: "DESTROYED",
            createTime: "2021-06-17T08:01:36.739860492Z",
            destroyEventTime: "2021-06-18T11:17:00.798768Z",
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
            generateTime: "2021-06-17T08:01:36.739860492Z",
        },
        purpose: "ENCRYPT_DECRYPT",
        createTime: "2021-06-17T08:01:36.739860492Z",
        nextRotationTime: "2021-09-14T19:00:00Z",
        rotationPeriod: "7776000s",
        versionTemplate: {
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
        },
    }
];

const images = [
    {
        "id": "1231",
        "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
        "name": "image-1",
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-1",
        "sourceDiskId": "4476293856257965646",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-1",
        "imageEncryptionKey": {
            "kmsKeyName": "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2/cryptoKeyVersions/1"
        },
        "kind": "compute#image"
    },
    {
        "id": 1232,
        "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
        "name": "image-2",
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-2",
        "sourceDiskId": "4476293856257965646",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-2",
        "labels": {"label-1": "test"},
        "kind": "compute#image"
    }
];

const createCache = (imageData, error, keysErr, keysList) => {
    return {
       
        cryptoKeys: {
            list: {
                'global': {
                    err: keysErr,
                    data: keysList
                }
            }
        },
        images: {
            list: {
                'global': {
                    data: imageData,
                    err: error
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [{ name: 'testproj' }]
                }
            }
        }
    }
};

describe('imagesCMKEncrypted', function () {
    describe('run', function () {
        
        it('should give unknown if unable to query compute images', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Compute Images');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error'],
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no compute images found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Compute Images found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if compute image has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[0]],
                null,
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if compute image does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[1]],
                null,
                null,
                cryptoKeys
            );


            plugin.run(cache, {}, callback);
        })
    })
});
