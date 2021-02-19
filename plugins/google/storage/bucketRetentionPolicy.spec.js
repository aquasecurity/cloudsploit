const expect = require('chai').expect;
var bucketRetentionPolicy = require('./bucketRetentionPolicy');

var failDate = new Date();
failDate.setMonth(failDate.getMonth() - 1);

const bucket = [
    {
        'kind': 'storage#bucket',
        'selfLink': 'https://www.googleapis.com/storage/v1/b/bucket-1',
        'id': 'bucket-1',
        'name': 'bucket-1',
        'projectNumber': '768447683925',
        'metageneration': '1',
        'location': 'US-EAST1',
        'storageClass': 'STANDARD',
        'etag': 'CAE=',
        'defaultEventBasedHold': false,
        'retentionPolicy': {
            'retentionPeriod': '864000',
            'effectiveTime': new Date(),
            'isLocked': true
        },
        'timeCreated': '2021-02-13T05:44:29.181Z',
        'updated': '2021-02-13T05:44:29.181Z',
        'locationType': 'region',
        'satisfiesPZS': false
    },
    {
        'kind': 'storage#bucket',
        'selfLink': 'https://www.googleapis.com/storage/v1/b/bucket-2',
        'id': 'bucket-2',
        'name': 'bucket-2',
        'projectNumber': '768447683925',
        'metageneration': '1',
        'location': 'US-EAST1',
        'storageClass': 'STANDARD',
        'etag': 'CAE=',
        'defaultEventBasedHold': false,
        'retentionPolicy': {
            'retentionPeriod': '86400',
            'effectiveTime': '2021-02-10T05:53:02.998Z',
            'isLocked': false
        },
        'timeCreated': '2021-02-13T05:44:29.181Z',
        'updated': '2021-02-13T05:44:29.181Z',
        'locationType': 'region',
        'satisfiesPZS': false
    },
    {
        'kind': 'storage#bucket',
        'selfLink': 'https://www.googleapis.com/storage/v1/b/bucket-3',
        'id': 'bucket-3',
        'name': 'bucket-3',
        'projectNumber': '768447683925',
        'metageneration': '1',
        'location': 'US-EAST1',
        'storageClass': 'STANDARD',
        'etag': 'CAE=',
        'defaultEventBasedHold': false,
        'retentionPolicy': {
            'retentionPeriod': '864000',
            'effectiveTime': new Date(),
            'isLocked': false
        },
        'timeCreated': '2021-02-13T05:44:29.181Z',
        'updated': '2021-02-13T05:44:29.181Z',
        'locationType': 'region',
        'satisfiesPZS': false
    },
    {
        'kind': 'storage#bucket',
        'selfLink': 'https://www.googleapis.com/storage/v1/b/bucket-4',
        'id': 'bucket-4',
        'name': 'bucket-4',
        'projectNumber': '768447683925',
        'metageneration': '1',
        'location': 'US-EAST1',
        'storageClass': 'STANDARD',
        'etag': 'CAE=',
        'defaultEventBasedHold': false,
        'timeCreated': '2021-02-13T05:44:29.181Z',
        'updated': '2021-02-13T05:44:29.181Z',
        'locationType': 'region',
        'satisfiesPZS': false
    },
    {
        'kind': 'storage#bucket',
        'selfLink': 'https://www.googleapis.com/storage/v1/b/bucket-5',
        'id': 'bucket-5',
        'name': 'bucket-5',
        'projectNumber': '768447683925',
        'metageneration': '1',
        'location': 'US-EAST1',
        'storageClass': 'STANDARD',
        'etag': 'CAE=',
        'defaultEventBasedHold': false,
        'retentionPolicy': {
            'retentionPeriod': '8640000',
            'effectiveTime': failDate,
            'isLocked': false
        },
        'timeCreated': '2021-02-13T05:44:29.181Z',
        'updated': '2021-02-13T05:44:29.181Z',
        'locationType': 'region',
        'satisfiesPZS': false
    }
];



const createCache = (bucketData, bucketErr) => {
    return {
        buckets: {
            list: {
                'global': {
                    err: bucketErr,
                    data: bucketData
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        buckets: {
            list: {
                'global': null
            }
        }
    }
}

describe('bucketRetentionPolicy', function () {
    describe('run', function () {
        it('should PASS if Storage bucket retention expiration is in more than set days', function (done) {
            const cache = createCache([bucket[0]]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '2' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Storage bucket retention expiration is in less than set days', function (done) {
            const cache = createCache([bucket[4]]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '90' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Storage bucket retention has already expired', function (done) {
            const cache = createCache([bucket[1]]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '5' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Storage bucket retention policy is not locked', function (done) {
            const cache = createCache([bucket[2]]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Storage bucket does not have aretention policy', function (done) {
            const cache = createCache([bucket[3]]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no storage buckets found', function (done) {
            const cache = createCache([]);
            bucketRetentionPolicy.run(cache, { bucket_retention_days: '10' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to query storage buckets', function (done) {
            const cache = createCache([], { message: 'Uanble to query storage buckets'});
            bucketRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list storage buckets response not found', function (done) {
            const cache = createNullCache();
            bucketRetentionPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
