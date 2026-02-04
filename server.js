// CommonJs
const fastify = require('fastify')({
  logger: true
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
        await request.jwtVerify();
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
         const token = fastify.jwt.sign({ id: userdetail.user_id, user_name: userdetail.user_name, role_id: userdetail.role_id });
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
    console.log(req.body);
   

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