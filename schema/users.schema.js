// validation schema
const createUserSchema = {
  body: {
    type: 'object',
    required: ['user_name', 'passwords', 'role_id'],
    properties: {
      user_name: {
        type: 'string',
        minLength: 3,
        errorMessage: 'Username must be at least 3 characters'
      },
      passwords: {
        type: 'string',
        minLength: 6,
        errorMessage: 'Password must be at least 6 characters'
      },
      role_id: {
        type: 'string',
        pattern: '^[0-9]+$',
        errorMessage: 'Please select a valid role'
      }
    },
    additionalProperties: false
  }
};

module.exports = createUserSchema;