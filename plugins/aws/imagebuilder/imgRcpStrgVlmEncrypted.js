var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Image Recipe Storage Volumes Encrypted',
    category: 'Imagebuilder',
    domain: 'compute',
    description: 'Ensure that Image Recipe storage ebs volumes are encrypted.',
    more_info: 'Image Builder is a fully managed AWS service that makes it easier to automate the creation, management, and deployment of customized, secure, and up-to-date server images that are pre-installed and pre-configured with software and settings to meet specific IT standards.',
    link: 'https://docs.aws.amazon.com/imagebuilder/latest/userguide/data-protection.html',
    recommended_action: 'Ensure that storage volumes for ebs are encrypted using AWS keys or customer managed keys in Image recipe',
    apis: ['Imagebuilder:listImageRecipes', 'Imagebuilder:getImageRecipe'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.imagebuilder, function(region, rcb){        
            var listImageRecipes = helpers.addSource(cache, source,
                ['imagebuilder', 'listImageRecipes', region]);

            if (!listImageRecipes) return rcb();

            if (listImageRecipes.err || !listImageRecipes.data) {
                helpers.addResult(results, 3,
                    `Unable to query for image recipe summary list: ${helpers.addError(listImageRecipes)}`, region);
                return rcb();
            }

            if (!listImageRecipes.data.length) {
                helpers.addResult(results, 0, 'No list image recipes found', region);
                return rcb();
            }

            for (let recipe of listImageRecipes.data) {
                if (!recipe.arn) continue;

                let resource = recipe.arn;

                var getImageRecipe = helpers.addSource(cache, source,
                    ['imagebuilder', 'getImageRecipe', region, recipe.arn]);

                if (!getImageRecipe || getImageRecipe.err || !getImageRecipe.data || !getImageRecipe.data.imageRecipe) {
                    helpers.addResult(results, 3,
                        `Unable to get image Recipe description: ${helpers.addError(getImageRecipe)}`,
                        region, resource);
                    continue;
                } 

                let result = getImageRecipe.data.imageRecipe.blockDeviceMappings.every(maping => maping.ebs && maping.ebs.encrypted);
                if (result) {
                    helpers.addResult(results, 0,
                        'Image recipe has ebs volume storage encrypted',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Image recipe does not have ebs volume storage encrypted',
                        region, resource);
                }

            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};