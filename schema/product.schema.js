const productSchema = {
        body: {
          type: 'object',
          required: ['product_name'],
          properties: {
            product_name: {
              type: 'string',
              minLength: 3,
              errorMessage: {
                minLength: 'Product name must be at least 3 characters long.'
              }
            }
          }
        }
      }
      
module.exports = productSchema;