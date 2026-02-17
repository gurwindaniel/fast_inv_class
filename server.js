// CommonJs
const fastify = require('fastify')({
  logger: true,
  ajv:{
    customOptions:{allErrors:true},
    plugins:[require('ajv-errors')],
  }
})
const createUserSchema = require('./schema/users.schema.js')
const pool=require('./db/pool.js')
const fastifyStatic = require('@fastify/static')
const bcryptjs=require('bcryptjs');

// Register fastify-static to serve static files
const path = require('path');

//Register JWT
fastify.register(require('@fastify/cookie'))
fastify.register(require('@fastify/jwt'), {
    secret:process.env.SECRET || 'supersecret',
    sign: {expiresIn: '1h'},
    cookie:{
        cookieName:'token',
        signed:false
    }
});

// Add authentication hook for protected routes using preHandler
fastify.addHook('preHandler', async (request, reply) => {
    // Allow public routes without authentication
    const publicRoutes = ['/', '/login'];
    const url = request.raw.url.split('?')[0];
    if (publicRoutes.includes(url)) return;

    try {
    const decoded = await request.jwtVerify();
    request.user = decoded; // Ensure req.user is set for all authenticated requests
    } catch (err) {
        return reply.redirect('/');
    }
});




//registger view engine
fastify.register(require('@fastify/view'), {
  engine:{ejs:require('ejs')},
  root:path.join(__dirname,'views')
})

fastify.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/public/',
});

fastify.register(require('@fastify/formbody'));


// ...existing code...
// ...existing code...
// ...existing code...

// Place this after all routes and plugin registrations, before fastify.listen
// Catch-all route: redirect to /users for admin, /address for others
// (This must be after fastify is initialized and all plugins/routes are registered)


// Serve root: redirect authenticated users based on role
fastify.get('/', async (request, reply) => {
  // Try to verify JWT from cookie if not already authenticated
  let user = request.user;
  if (!user && request.cookies && request.cookies.token) {
    try {
      user = fastify.jwt.verify(request.cookies.token);
    } catch (err) {
      // Invalid token, treat as not authenticated
      user = null;
    }
  }
  if (user) {
    if (user.role_id === 1) {
      return reply.redirect('/users');
    } else {
      return reply.redirect('/address');
    }
  }
  return reply.view('login.ejs', { currentUser: null, error: false });
});

fastify.post('/login', async(req,reply)=>{
  const {user_name,passwords}=req.body


  try{

    const users=await pool.query('select * from users where user_name=$1',[user_name])
    console.log(users.rows[0])
    const userdetail=users.rows[0]
    if(users.rows.length>0){
       const isMatch=await bcryptjs.compare(passwords,userdetail.passwords)
       
        if(!isMatch){
          return reply.view('login.ejs',{currentUser:req.user,error:"Password Incorrect"})
        }
         const token = fastify.jwt.sign({ user_id: userdetail.user_id, user_name: userdetail.user_name, role_id: userdetail.role_id });
         console.log(token)
         reply.setCookie('token', token, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'lax',
                });
        if (userdetail.role_id === 1) {
          return reply.redirect('/users');
        } else {
          return reply.redirect('/address');
        }
    }else{
      return reply.view('login.ejs',{error:"User Invalid"})
    }
   
  }catch(e){
   return reply.view('login.ejs',{error:"Server Error"})

  }

})



// Only allow admin to access /users and create users
fastify.get('/users', async (request, reply) => {
  if (!request.user || request.user.role_id !== 1) {
    return reply.code(403).send('Forbidden: Only admin can access this page.');
  }
  const roles = await pool.query('SELECT * FROM roles');
  return reply.view('users.ejs', {
    roles: roles.rows,
    currentUser: request.user,
    errors: null,
    formData: {},
    success: null,
    error: null
  });
});

// Handle user creation (admin only)
fastify.post('/users/create', async (request, reply) => {
  if (!request.user || request.user.role_id !== 1) {
    return reply.code(403).send('Forbidden: Only admin can create users.');
  }
  const { user_name, passwords, role_id } = request.body;
  const roles = await pool.query('SELECT * FROM roles');
  let errors = [];
  let formData = { user_name, role_id };
  // Basic validation
  if (!user_name || !passwords || !role_id) {
    errors.push('All fields are required.');
  }
  // Check if username already exists
  const existing = await pool.query('SELECT * FROM users WHERE user_name = $1', [user_name]);
  if (existing.rows.length > 0) {
    errors.push('Username already exists.');
  }
  if (errors.length > 0) {
    return reply.view('users.ejs', {
      roles: roles.rows,
      currentUser: request.user,
      errors,
      formData,
      success: null,
      error: null
    });
  }
  try {
    // Hash password
    const hashedPassword = await bcryptjs.hash(passwords, 10);
    // Insert user
    const result = await pool.query(
      'INSERT INTO users (user_name, passwords, role_id) VALUES ($1, $2, $3) RETURNING user_id',
      [user_name, hashedPassword, parseInt(role_id, 10)]
    );
    return reply.view('users.ejs', {
      roles: roles.rows,
      currentUser: request.user,
      errors: null,
      formData: {},
      success: `User created successfully! User ID: ${result.rows[0].user_id}`,
      error: null
    });
  } catch (err) {
    return reply.view('users.ejs', {
      roles: roles.rows,
      currentUser: request.user,
      errors: null,
      formData,
      success: null,
      error: err.message || 'Failed to create user.'
    });
  }
});

  // ...existing code...

 // Display address form
  fastify.get('/address', 
    { preHandler: fastify.authenticate },
    async (req, reply) => {
      try {
        const personTypes = await pool.query(
          "SELECT type_id, person_type FROM person_type ORDER BY type_id ASC"
        );
        
        return reply.view('address.ejs', {
          personTypes: personTypes.rows,
          currentUser: req.user || null,
          message: null,
          error: null
        });
      } catch (err) {
        console.error(err);
        return reply.view('address.ejs', {
          personTypes: [],
          currentUser: req.user || null,
          message: null,
          error: 'Failed to load person types'
        });
      }
    }
  );

  // Handle address creation
  fastify.post('/address/create', async (req, reply) => {
      try {
        const { address_name, type_id, locations, pincode } = req.body;
        const user_id = req.user.user_id;

        // Validate type_id and pincode are valid integers
        const typeIdInt = parseInt(type_id, 10);
        const pincodeInt = parseInt(pincode, 10);
        if (isNaN(typeIdInt) || isNaN(pincodeInt)) {
          const personTypes = await pool.query(
            "SELECT type_id, person_type FROM person_type ORDER BY type_id ASC"
          );
          return reply.view('address.ejs', {
            personTypes: personTypes.rows,
            currentUser: req.user || null,
            message: null,
            error: 'Invalid type or pincode. Please enter valid numbers.'
          });
        }

        const result = await pool.query(
          "INSERT INTO address (address_name, type_id, locations, pincode, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING address_id",
          [address_name, typeIdInt, locations, pincodeInt, user_id]
        );

        // Fetch person types to re-render form with success message
        const personTypes = await pool.query(
          "SELECT type_id, person_type FROM person_type ORDER BY type_id ASC"
        );

        return reply.view('address.ejs', {
          personTypes: personTypes.rows,
          currentUser: req.user || null,
          message: `Address created successfully! Address ID: ${result.rows[0].address_id}`,
          error: null
        });
      } catch (err) {
        console.error('Address creation error:', err);
        const personTypes = await pool.query(
          "SELECT type_id, person_type FROM person_type ORDER BY type_id ASC"
        );
        return reply.view('address.ejs', {
          personTypes: personTypes.rows,
          currentUser: req.user || null,
          message: null,
          error: err.message || 'Failed to create address'
        });
      }
    }
  );

  // Optional: Display list of user's addresses
  fastify.get('/address/list',
    { preHandler: fastify.authenticate },
    async (req, reply) => {
      try {
        const addresses = await pool.query(
          `SELECT a.address_id, a.address_name, pt.person_type, a.locations, a.pincode, a.address_date
           FROM address a
           JOIN person_type pt ON a.type_id = pt.type_id
           WHERE a.user_id = $1
           ORDER BY a.address_date DESC`,
          [req.user.user_id]
        );

        return reply.view('addressList.ejs', {
          addresses: addresses.rows,
          currentUser: req.user || null
        });
      } catch (err) {
        console.error(err);
        return reply.send({ error: err.message });
      }
    }
  );

 // Display product creation form
  fastify.get('/product',
    async (req, reply) => {
      try {
        const products = await pool.query(
          "SELECT product_id, product_name FROM product ORDER BY product_id ASC"
        );

        return reply.view('product.ejs', {
          products: products.rows,
          currentUser: req.user || null,
          message: null,
          error: null
        });
      } catch (err) {
        console.error(err);
        return reply.view('product.ejs', {
          products: [],
          currentUser: req.user || null,
          message: null,
          error: 'Failed to load products'
        });
      }
    }
  );



   // Handle product creation
  fastify.post('/product/create',
    {
      schema: require('./schema/product.schema.js'),
      attachValidation: true
    },
    async (req, reply) => {
      try {
        const { product_name } = req.body;

        const result = await pool.query(
          "INSERT INTO product (product_name) VALUES ($1) RETURNING product_id",
          [product_name]
        );

        // Fetch all products to re-render
        const products = await pool.query(
          "SELECT product_id, product_name FROM product ORDER BY product_id ASC"
        );

        return reply.view('product.ejs', {
          products: products.rows,
          currentUser: req.user || null,
          message: `Product "${product_name}" created successfully! Product ID: ${result.rows[0].product_id}`,
          error: null
        });
      } catch (err) {
        console.error('Product creation error:', err);

        const products = await pool.query(
          "SELECT product_id, product_name FROM product ORDER BY product_id ASC"
        );

        return reply.view('product.ejs', {
          products: products.rows,
          currentUser: req.user || null,
          message: null,
          error: err.message || 'Failed to create product'
        });
      }
    }
  );

   // Get all products (JSON endpoint for AJAX, optional)
  fastify.get('/product/api/list',
    async (req, reply) => {
      try {
        const products = await pool.query(
          "SELECT product_id, product_name FROM product ORDER BY product_id ASC"
        );
        return reply.send(products.rows);
      } catch (err) {
        console.error(err);
        return reply.send({ error: err.message });
      }
    }
  );

  // Delete product by ID
fastify.post('/product/delete/:id', async (req, reply) => {
  const productId = parseInt(req.params.id, 10);
  let message = null;
  let error = null;
  try {
    if (isNaN(productId)) {
      throw new Error('Invalid product ID.');
    }
    // Attempt to delete the product
    const result = await pool.query('DELETE FROM product WHERE product_id = $1 RETURNING *', [productId]);
    if (result.rowCount === 0) {
      error = 'Product not found or already deleted.';
    } else {
      message = `Product ID ${productId} deleted successfully.`;
    }
  } catch (err) {
    error = err.message || 'Failed to delete product.';
  }
  // Fetch all products to re-render
  const products = await pool.query('SELECT product_id, product_name FROM product ORDER BY product_id ASC');
  return reply.view('product.ejs', {
    products: products.rows,
    currentUser: req.user || null,
    message,
    error
  });
});

// fastify product
// Logout route
fastify.get('/logout', async (req, reply) => {
    reply.clearCookie('token');
    return reply.redirect('/');
});


// Catch-all route: redirect to /users for admin, /address for others
fastify.setNotFoundHandler(async (request, reply) => {
  let user = request.user;
  if (!user && request.cookies && request.cookies.token) {
    try {
      user = fastify.jwt.verify(request.cookies.token);
    } catch (err) {
      user = null;
    }
  }
  if (user) {
    if (user.role_id === 1) {
      return reply.redirect('/users');
    } else {
      return reply.redirect('/address');
    }
  }
  return reply.redirect('/');
});

// Display GRN form
fastify.get('/grn', async (req, reply) => {
  try {
    // Fetch addresses and products for dropdowns
    const addresses = await pool.query('SELECT address_id, address_name FROM address ORDER BY address_name ASC');
    const products = await pool.query('SELECT product_id, product_name FROM product ORDER BY product_name ASC');
    return reply.view('grn.ejs', {
      addresses: addresses.rows,
      products: products.rows,
      currentUser: req.user || null,
      message: null,
      error: null
    });
  } catch (err) {
    console.error('GRN form error:', err);
    return reply.view('grn.ejs', {
      addresses: [],
      products: [],
      currentUser: req.user || null,
      message: null,
      error: 'Failed to load GRN form'
    });
  }
});

// Handle GRN creation
fastify.post('/grn', async (req, reply) => {
  try {
    const { address_id, product_id, grn_amount, grn_quantity } = req.body;
    const user_id = req.user.user_id;
    // Validate input
    if (!address_id || !product_id || !grn_amount || !grn_quantity) {
      throw new Error('All fields are required.');
    }
    const result = await pool.query(
      'INSERT INTO grn (address_id, product_id, grn_amount, grn_quantity, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING grn_id',
      [parseInt(address_id, 10), parseInt(product_id, 10), parseFloat(grn_amount), parseInt(grn_quantity, 10), user_id]
    );
    // Fetch addresses and products for re-render
    const addresses = await pool.query('SELECT address_id, address_name FROM address ORDER BY address_name ASC');
    const products = await pool.query('SELECT product_id, product_name FROM product ORDER BY product_name ASC');
    return reply.view('grn.ejs', {
      addresses: addresses.rows,
      products: products.rows,
      currentUser: req.user || null,
      message: `GRN created successfully! GRN ID: ${result.rows[0].grn_id}`,
      error: null
    });
  } catch (err) {
    console.error('GRN creation error:', err);
    // Fetch addresses and products for re-render
    const addresses = await pool.query('SELECT address_id, address_name FROM address ORDER BY address_name ASC');
    const products = await pool.query('SELECT product_id, product_name FROM product ORDER BY product_name ASC');
    return reply.view('grn.ejs', {
      addresses: addresses.rows,
      products: products.rows,
      currentUser: req.user || null,
      message: null,
      error: err.message || 'Failed to create GRN'
    });
  }
});

// List all GRNs for the current user
fastify.get('/grn/list', { preHandler: fastify.authenticate }, async (req, reply) => {
  try {
    const grns = await pool.query(`
      SELECT g.grn_id, g.grn_date, g.grn_amount, g.grn_quantity,
             a.address_name, p.product_name
        FROM grn g
        JOIN address a ON g.address_id = a.address_id
        JOIN product p ON g.product_id = p.product_id
        WHERE g.user_id = $1
        ORDER BY g.grn_date DESC
    `, [req.user.user_id]);
    return reply.view('grnList.ejs', {
      grns: grns.rows,
      currentUser: req.user || null
    });
  } catch (err) {
    console.error('GRN list error:', err);
    return reply.send({ error: err.message });
  }
});



// Handle Invoice creation


fastify.post('/invoice', async (req, reply) => {
  try {
    const { customer_address_id } = req.body;
    const user_id = req.user.user_id;
    if (!customer_address_id) {
      throw new Error('Customer address is required.');
    }
    const result = await pool.query(
      'INSERT INTO invoice (address_id, user_id) VALUES ($1, $2) RETURNING invoice_id',
      [parseInt(customer_address_id, 10), user_id]
    );
    // Fetch customer and vendor addresses for re-render
    const customerAddresses = await pool.query(`
      SELECT a.address_id, a.address_name
      FROM address a
      JOIN person_type pt ON a.type_id = pt.type_id
      WHERE pt.person_type = 'Customer'
      ORDER BY a.address_name ASC
    `);
    const vendorAddresses = await pool.query(`
      SELECT a.address_id, a.address_name
      FROM address a
      JOIN person_type pt ON a.type_id = pt.type_id
      WHERE pt.person_type = 'Vendor'
      ORDER BY a.address_name ASC
    `);
    return reply.view('invoice.ejs', {
      customerAddresses: customerAddresses.rows,
      vendorAddresses: vendorAddresses.rows,
      currentUser: req.user || null,
      message: `Invoice created successfully! Invoice ID: ${result.rows[0].invoice_id}`,
      error: null
    });
  } catch (err) {
    console.error('Invoice creation error:', err);
    // Fetch customer and vendor addresses for re-render
    const customerAddresses = await pool.query(`
      SELECT a.address_id, a.address_name
      FROM address a
      JOIN person_type pt ON a.type_id = pt.type_id
      WHERE pt.person_type = 'Customer'
      ORDER BY a.address_name ASC
    `);
    const vendorAddresses = await pool.query(`
      SELECT a.address_id, a.address_name
      FROM address a
      JOIN person_type pt ON a.type_id = pt.type_id
      WHERE pt.person_type = 'Vendor'
      ORDER BY a.address_name ASC
    `);
    return reply.view('invoice.ejs', {
      customerAddresses: customerAddresses.rows,
      vendorAddresses: vendorAddresses.rows,
      currentUser: req.user || null,
      message: null,
      error: err.message || 'Failed to create invoice'
    });
  }
});

// --- INVOICE ROUTES (user-specific, single-line invoice) ---
// Render invoice creation page
fastify.get('/invoice', { preHandler: fastify.authenticate }, async (req, reply) => {
  try {
    // Customer addresses (person_type = 'Customer') belonging to this user
    const customerAddresses = await pool.query(
      `SELECT a.address_id, a.address_name
         FROM address a
         JOIN person_type pt ON a.type_id = pt.type_id
         WHERE pt.person_type = 'Customer' AND a.user_id = $1
         ORDER BY a.address_id ASC`,
      [req.user.user_id]
    );
    // Vendor addresses (person_type = 'Vendor') belonging to this user
    const vendorAddresses = await pool.query(
      `SELECT a.address_id, a.address_name
         FROM address a
         JOIN person_type pt ON a.type_id = pt.type_id
         WHERE pt.person_type = 'Vendor' AND a.user_id = $1
         ORDER BY a.address_id ASC`,
      [req.user.user_id]
    );
    // Fetch all products for this user (products received in any GRN or all products if you want to show all)
    const products = await pool.query(
      `SELECT DISTINCT p.product_id, p.product_name
         FROM product p
         LEFT JOIN grn g ON p.product_id = g.product_id AND g.user_id = $1
         ORDER BY p.product_name ASC`,
      [req.user.user_id]
    );
    return reply.view('invoice.ejs', {
      customerAddresses: customerAddresses.rows,
      vendorAddresses: vendorAddresses.rows,
      products: products.rows,
      currentUser: req.user || null,
      message: null,
      error: null
    });
  } catch (err) {
    console.error('Invoice page error:', err);
    return reply.view('invoice.ejs', {
      customerAddresses: [],
      vendorAddresses: [],
      products: [],
      currentUser: req.user || null,
      message: null,
      error: 'Failed to load invoice form data'
    });
  }
});

// AJAX: get products supplied by a vendor (distinct products from GRN)
fastify.get('/invoice/vendor-products', { preHandler: fastify.authenticate }, async (req, reply) => {
  try {
    const vendorId = parseInt(req.query.vendor_id);
    const customerId = req.query.customer_id ? parseInt(req.query.customer_id) : null;
    if (isNaN(vendorId)) return reply.code(400).send({ error: 'Invalid vendor id' });
    let products;
    if (customerId && !isNaN(customerId)) {
      // Filter by both vendor and customer: only products received from this vendor and sold to this customer
      products = await pool.query(
        `SELECT DISTINCT p.product_id, p.product_name,
                COALESCE(AVG(g.grn_amount::numeric), 0) AS received_price
           FROM product p
           JOIN grn g ON p.product_id = g.product_id
           WHERE g.address_id = $1 AND g.user_id = $2
             AND EXISTS (SELECT 1 FROM address a WHERE a.address_id = $3)
           GROUP BY p.product_id, p.product_name
           ORDER BY p.product_name ASC`,
        [vendorId, req.user.user_id, customerId]
      );
    } else {
      // Only filter by vendor
      products = await pool.query(
        `SELECT p.product_id, p.product_name,
                COALESCE(AVG(g.grn_amount::numeric), 0) AS received_price
           FROM product p
           JOIN grn g ON p.product_id = g.product_id
           WHERE g.address_id = $1 AND g.user_id = $2
           GROUP BY p.product_id, p.product_name
           ORDER BY p.product_name ASC`,
        [vendorId, req.user.user_id]
      );
    }
    return reply.send(products.rows);
  } catch (err) {
    console.error('Vendor products error:', err);
    return reply.code(500).send({ error: err.message });
  }
});

// Create invoice and a sale line (single-line invoice)
fastify.post('/invoice/create', { preHandler: fastify.authenticate }, async (req, reply) => {
  try {
    const { customer_address_id, vendor_address_id, product_id, sale_quantity, sale_amount } = req.body;
    const user_id = req.user.user_id;
    if (!customer_address_id || !product_id || !sale_quantity || !sale_amount) {
      throw new Error('Missing required fields');
    }
    // Ensure customer_address_id belongs to this user and is a Customer
    const custCheck = await pool.query(
      `SELECT a.address_id FROM address a JOIN person_type pt ON a.type_id = pt.type_id
         WHERE a.address_id = $1 AND a.user_id = $2 AND pt.person_type = 'Customer'`,
      [parseInt(customer_address_id), user_id]
    );
    if (custCheck.rows.length === 0) throw new Error('Invalid customer address selected');
    // If vendor_address_id provided, ensure it belongs to user and is Vendor
    let vendorId = null;
    if (vendor_address_id) {
      const vendorCheck = await pool.query(
        `SELECT a.address_id FROM address a JOIN person_type pt ON a.type_id = pt.type_id
           WHERE a.address_id = $1 AND a.user_id = $2 AND pt.person_type = 'Vendor'`,
        [parseInt(vendor_address_id), user_id]
      );
      if (vendorCheck.rows.length === 0) throw new Error('Invalid vendor address selected');
      vendorId = parseInt(vendor_address_id);
    }
    // Create invoice
    const invRes = await pool.query(
      'INSERT INTO invoice (address_id, user_id) VALUES ($1, $2) RETURNING invoice_id',
      [parseInt(customer_address_id), user_id]
    );
    const invoiceId = invRes.rows[0].invoice_id;
    // Insert sale line
    const saleRes = await pool.query(
      `INSERT INTO sale (invoice_id, product_id, grn_id, vendor_address_id, sale_amount, sale_quantity, user_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING sale_id`,
      [invoiceId, parseInt(product_id), null, vendorId, parseFloat(sale_amount), parseInt(sale_quantity), user_id]
    );
    return reply.view('invoice.ejs', {
      customerAddresses: (await pool.query(`SELECT a.address_id, a.address_name FROM address a JOIN person_type pt ON a.type_id=pt.type_id WHERE pt.person_type='Customer' AND a.user_id=$1`, [user_id])).rows,
      vendorAddresses: (await pool.query(`SELECT a.address_id, a.address_name FROM address a JOIN person_type pt ON a.type_id=pt.type_id WHERE pt.person_type='Vendor' AND a.user_id=$1`, [user_id])).rows,
      products: [],
      currentUser: req.user || null,
      message: `Invoice ${invoiceId} created. Sale ID: ${saleRes.rows[0].sale_id}`,
      error: null
    });
  } catch (err) {
    console.error('Invoice create error:', err);
    const user_id = req.user && req.user.user_id;
    return reply.view('invoice.ejs', {
      customerAddresses: user_id ? (await pool.query(`SELECT a.address_id, a.address_name FROM address a JOIN person_type pt ON a.type_id=pt.type_id WHERE pt.person_type='Customer' AND a.user_id=$1`, [user_id])).rows : [],
      vendorAddresses: user_id ? (await pool.query(`SELECT a.address_id, a.address_name FROM address a JOIN person_type pt ON a.type_id=pt.type_id WHERE pt.person_type='Vendor' AND a.user_id=$1`, [user_id])).rows : [],
      products: [],
      currentUser: req.user || null,
      message: null,
      error: err.message || 'Failed to create invoice'
    });
  }
});

// List invoices and sales for the user
fastify.get('/invoice/list', { preHandler: fastify.authenticate }, async (req, reply) => {
  try {
    const rows = await pool.query(
      `SELECT i.invoice_id, i.invoice_date, c.address_name AS customer_address,
                s.sale_id, p.product_name, s.sale_quantity, s.sale_amount, v.address_name AS vendor_address
         FROM invoice i
         JOIN sale s ON s.invoice_id = i.invoice_id
         JOIN product p ON s.product_id = p.product_id
         LEFT JOIN address v ON s.vendor_address_id = v.address_id
         JOIN address c ON i.address_id = c.address_id
         WHERE i.user_id = $1
         ORDER BY i.invoice_date DESC`,
      [req.user.user_id]
    );
    return reply.view('invoiceList.ejs', { rows: rows.rows, currentUser: req.user || null });
  } catch (err) {
    console.error('Invoice list error:', err);
    return reply.send({ error: err.message });
  }
});

// Dashboard page
  fastify.get('/dashboard', { preHandler: fastify.authenticate }, async (req, reply) => {
    try {
      // load vendor addresses for the current user
      const vendors = await pool.query(
        `SELECT a.address_id, a.address_name
         FROM address a
         JOIN person_type pt ON a.type_id = pt.type_id
         WHERE pt.person_type = 'Vendor' AND a.user_id = $1
         ORDER BY a.address_name`,
        [req.user.user_id]
      );

      return reply.view('dashboard.ejs', {
        vendors: vendors.rows,
        currentUser: req.user || null
      });
    } catch (err) {
      console.error('Dashboard render error:', err);
      return reply.view('dashboard.ejs', { vendors: [], currentUser: req.user || null, error: 'Failed to load dashboard' });
    }
  });

  // API: overall summary (sales, estimated purchase cost, profit)
  fastify.get('/dashboard/summary', { preHandler: fastify.authenticate }, async (req, reply) => {
    try {
      const userId = req.user.user_id;

      const totalSalesQ = `SELECT COALESCE(SUM(sale_amount * sale_quantity),0) AS total_sales FROM sale WHERE user_id = $1`;
      const totalPurchaseQ = `SELECT COALESCE(SUM(g.grn_amount * g.grn_quantity),0) AS estimated_purchase_cost FROM grn g WHERE g.user_id = $1`;
      const [totalSales, totalPurchase] = await Promise.all([
        pool.query(totalSalesQ, [userId]),
        pool.query(totalPurchaseQ, [userId])
      ]);
      const total_sales = totalSales.rows[0].total_sales || 0;
      const estimated_purchase_cost = totalPurchase.rows[0].estimated_purchase_cost || 0;
      const profit = total_sales - estimated_purchase_cost;
      return reply.send({ total_sales, estimated_purchase_cost, profit });
    } catch (err) {
      console.error('Dashboard summary error:', err);
      return reply.code(500).send({ error: err.message });
    }
  });

  // API: vendor -> product profit/stats
  fastify.get('/dashboard/vendor-products', { preHandler: fastify.authenticate }, async (req, reply) => {
    try {
      const vendorId = parseInt(req.query.vendor_id);
      const userId = req.user.user_id;
      if (isNaN(vendorId)) return reply.code(400).send({ error: 'Invalid vendor id' });

      const q = `
  WITH grn_stats AS (
        -- total received cost = sum of grn_amount (each grn_amount is already a total for that GRN row)
        SELECT product_id, SUM(grn_quantity) AS received_qty, SUM(grn_amount) AS received_cost
    FROM grn
    WHERE address_id = $1 AND user_id = $2
    GROUP BY product_id
  ), sale_stats AS (
    -- sales that are linked to this vendor either by vendor_address_id or by originating GRN
        -- sale_amount is stored as total sale amount for the sale row
        SELECT product_id, SUM(sale_quantity) AS sold_qty, SUM(sale_amount) AS sales_amount
    FROM sale
    WHERE user_id = $2 AND (vendor_address_id = $1 OR grn_id IN (SELECT grn_id FROM grn WHERE address_id = $1 AND user_id = $2))
    GROUP BY product_id
  )
SELECT p.product_id, p.product_name,
       COALESCE(g.received_qty,0) AS received_qty,
       COALESCE(g.received_cost,0) AS received_cost,
       COALESCE(s.sold_qty,0) AS sold_qty,
       COALESCE(s.sales_amount,0) AS sales_amount,
      -- profit as requested: (sales_amount * sold_qty) - (received_cost * sold_qty)
      (COALESCE(s.sales_amount,0) * COALESCE(s.sold_qty,0) - COALESCE(g.received_cost,0) * COALESCE(s.sold_qty,0)) AS profit_est
FROM product p
JOIN grn_stats g ON p.product_id = g.product_id
LEFT JOIN sale_stats s ON p.product_id = s.product_id
ORDER BY profit_est DESC;
      `;

      const res = await pool.query(q, [vendorId, userId]);
      return reply.send(res.rows);
    } catch (err) {
      console.error('Vendor products error:', err);
      return reply.code(500).send({ error: err.message });
    }
  });


// Run the server!
fastify.listen({ port: 3000 }, (err, address) => {
  if (err) throw err
  // Server is now listening on ${address}
  fastify.log.info(`server listening on ${address}`)
})