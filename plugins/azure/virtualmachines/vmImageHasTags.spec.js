var expect = require('chai').expect;
var vmImageHasTags = require('./vmImageHasTags');

const images = [
    {
        'name': 'test-image',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/images/test-ali-ss',
        'type': 'Microsoft.Compute/image',
        'location': 'eastus',
        'diskSizeGB': 30,
        'tags': { 'key': 'value' }
    },
    {
        'name': 'test-image',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/images/test-ali-ss',
        'type': 'Microsoft.Compute/image',
        'location': 'eastus',
        'diskSizeGB': 30,
        'tags': {}
    }
];

const createCache = (images) => {
    let image = {};
    if (images) {
        image['data'] = images;
    }
    return {
        images: {
            list: {
                'eastus': image
            }
        }
    };
};

describe('vmImageHasTags', function() {
    describe('run', function() {
        it('should give passing result if no images found', function(done) {
            const cache = createCache([]);
            vmImageHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No virtual machine image found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for images', function(done) {
            const cache = createCache(null);
            vmImageHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine image :');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if image has tags associated', function(done) {
            const cache = createCache([images[0]]);

            vmImageHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM Image has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if image does not have tags associated', function(done) {
            const cache = createCache([images[1]]);

            vmImageHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM Image does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});