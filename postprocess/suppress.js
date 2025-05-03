module.exports = {
    create: function(suppressions) {
        // Creates an object that can post process results to suppress rules
        // This allows the client to set to ignore particular failures so that
        // they don't affect the overall score
        // Suppressions have the format pluginId:region:resourceId, where any
        // of the items can be * to indicate match all.
        if (!suppressions) suppressions = [];

        // Validate suppression format
        const validateSuppression = (expr) => {
            // Check basic format (three parts separated by colons)
            const parts = expr.split(':');
            if (parts.length !== 3) {
                throw new Error(`Invalid suppression format: ${expr}. Expected format: pluginId:region:resourceId`);
            }
            
            const pluginPattern = /^[A-Za-z0-9*]{1,255}$/; // eslint-disable-line
            const regionPattern = /^[A-Za-z0-9\-_]{1,255}$/; // eslint-disable-line
            const resourcePattern = /^[ A-Za-z0-9._~()'!*:@,;+?#$%^&={}\\[\]\\|\"/-]{1,255}$/;  // eslint-disable-line
            const [pluginId, region, resourceId] = parts;
            
            // Validate pluginId
            if (!pluginPattern.test(pluginId)) {
                throw new Error(`Invalid pluginId in suppression: ${pluginId}. Must only contain letters and numbers and be between 1-255 characters.`);
            }

            // Validate region
            if (!regionPattern.test(region)) {
                throw new Error(`Invalid region in suppression: ${region}. Must only contain letters, numbers, hyphen (-), and underscore (_) and be between 1-255 characters.`);
            }

            // Validate resourceId with specific pattern
            if (!resourcePattern.test(resourceId)) {
                throw new Error(`Invalid resourceId in suppression: ${resourceId}. Must match allowed pattern and be between 1-255 characters.`);
            }

            return true;
        };

        // Validate and create expressions
        var expressions = suppressions
            .map(function(expr) {
                // Validate the expression format
                validateSuppression(expr);

                // Escape special regex characters except * which we handle specially
                const escapedExpr = expr
                    .replace(/[.+?^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
                    .split('*')
                    .join('.*'); // Replace * with .*

                return [
                    expr,
                    new RegExp('^' + escapedExpr + '$')
                ];
            });

        return function(result) {
            var match = expressions.find(function(expression) {
                return expression[1].test(result);
            });

            return match && match[0];
        };
    }
};
