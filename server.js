// CommonJs
const fastify = require('fastify')({
  logger: true,
  ajv:{
    customOptions:{allErrors:true},
    plugins:[require('ajv-errors')],
  }
})
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
// Serve index.html at root
fastify.get('/', (request, reply) => {
  return reply.view('login.ejs',{currentUser:request.user,error:false}); // index.html must be in the 'public' directory
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
        return reply.redirect('/users')
    }else{
      return reply.view('login.ejs',{error:"User Invalid"})
    }
   
  }catch(e){
   return reply.view('login.ejs',{error:"Server Error"})

  }

})



fastify.get('/users', async(request, reply) => {
const roles=await pool.query('SELECT * FROM roles')

 
  try{
 return reply.view('users.ejs', { currentUser: request.user , roles:roles.rows})
  }catch(err){
    console.error(err)
    return reply.status(500).send('Server Error')
  }
})

//submit users

 // Handle form POST
  fastify.post('/users/create', async (req, reply) => {
    const { user_name, passwords, role_id } = req.body;

    try {
       let roleid =Number(role_id);
       //hash password
       const saltRounds=10;
       const hashedPassword=await bcryptjs.hash(passwords,saltRounds);
        await pool.query(
            "INSERT INTO users (user_name, passwords, role_id) VALUES ($1, $2, $3)",
            [user_name, hashedPassword, roleid]
        );

        return reply.send({ success: true, message: "User created" });

    } catch (err) {
        return reply.send({ success: false, message: err.message });
    }
});

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
        const user_id = req.user.id;

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
          [req.user.id]
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

// Logout route
fastify.get('/logout', async (req, reply) => {
    reply.clearCookie('token');
    return reply.redirect('/');
});

// Run the server!
fastify.listen({ port: 3000 }, (err, address) => {
  if (err) throw err
  // Server is now listening on ${address}
  fastify.log.info(`server listening on ${address}`)
})