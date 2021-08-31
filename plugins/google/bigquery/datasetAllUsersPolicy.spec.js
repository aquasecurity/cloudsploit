var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./datasetAllUsersPolicy');

const datasetGet = [
    {
        "kind": "bigquery#dataset",
        "id": "aqua-dev-cloudsploit:aqua_ds",
        "selfLink": "https://www.googleapis.com/bigquery/v2/projects/aqua-dev-cloudsploit/datasets/aqua_ds",
        "datasetReference": { "datasetId": "aqua_ds", "projectId": "aqua-dev-cloudploit" },
        "access": [
          { "role": "WRITER", "specialGroup": "projectWriters" },
          { "role": "OWNER", "specialGroup": "projectOwners" },
          { "role": "READER", "specialGroup": "projectReaders" }
        ],
        "creationTime": "1619622395743",
        "lastModifiedTime": "1619699668544",
        "location": "US",
        "type": "DEFAULT"
    },
    {
        "kind": "bigquery#dataset",
        "id": "aqua-dev-cloudsploit:aqua_ds",
        "selfLink": "https://www.googleapis.com/bigquery/v2/projects/aqua-dev-cloudsploit/datasets/aqua_ds",
        "datasetReference": { "datasetId": "aqua_ds", "projectId": "aqua-dev-cloudploit" },
        "access": [
          { "role": "WRITER", "iamMember": "allUsers" },
          { "role": "WRITER", "specialGroup": "projectWriters" },
          { "role": "OWNER", "specialGroup": "projectOwners" },
          { "role": "READER", "specialGroup": "allAuthenticatedUsers" },
          { "role": "READER", "specialGroup": "projectReaders" }
        ],
        "creationTime": "1619622395743",
        "lastModifiedTime": "1619699668544",
        "location": "US",
        "type": "DEFAULT"
    }
];

const createCache = (err, data) => {
    return {
        datasets: {
            get: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('datasetAllUsersPolicy', function () {
    describe('run', function () {
        it('should give unknown result if unable to query BigQuery datasets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query BigQuery datasets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no datasets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No BigQuery datasets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if BigQuery dataset does not provide public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('BigQuery dataset does not provide public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasetGet[0]]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if BigQuery dataset provides public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('BigQuery dataset provides');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasetGet[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
});