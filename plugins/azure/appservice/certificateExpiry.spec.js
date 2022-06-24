var expect = require('chai').expect;
var certificateExpiry = require('./certificateExpiry');

let sufficientTime = new Date(new Date().setDate(new Date().getDate() + 70)).toISOString();
let notSufficientTime = new Date(new Date().setDate(new Date().getDate() + 40)).toISOString();
let expired = new Date(new Date().setDate(new Date().getDate() - 7)).toISOString();
console.log(sufficientTime);
console.log(notSufficientTime);
console.log(expired);
const certificates = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/certificates/test-cert',
        'name': 'test-cert',
        'type': 'Microsoft.Web/certificates',
        'location': 'East US',
        'expirationDate': sufficientTime
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/certificates/test-cert',
        'name': 'test-cert',
        'type': 'Microsoft.Web/certificates',
        'location': 'East US',
        'expirationDate': notSufficientTime
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/certificates/test-cert',
        'name': 'test-cert',
        'type': 'Microsoft.Web/certificates',
        'location': 'East US',
        'expirationDate': expired
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/certificates/test-cert',
        'name': 'test-cert',
        'type': 'Microsoft.Web/certificates',
        'location': 'East US'
    }
];

const createCache = (certificates) => {
    let certs = {};

    if (certificates) {
        certs['data'] = certificates;
    }

    return {
        appServiceCertificates: {
            list: {
                'eastus': certs
            }
        }
    };
};

describe('certificateExpiry', function() {
    describe('run', function() {
        it('should give passing result if no certificates', function(done) {
            const cache = createCache([]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Service Certificates found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for certificates', function(done) {
            const cache = createCache();
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Service Certificates');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to expiration date is not configured', function(done) {
            const cache = createCache([certificates[3]]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('App Service Certificate does not have an expiration date configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if certificate has sufficient time in expiry', function(done) {
            const cache = createCache([certificates[0]]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service Certificate expires in 70 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if certificate does not have sufficient time in expiry', function(done) {
            const cache = createCache([certificates[1]]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service Certificate expires in 40 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if certificate is expired already', function(done) {
            const cache = createCache([certificates[2]]);
            certificateExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service Certificate expired 7 days ago');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});