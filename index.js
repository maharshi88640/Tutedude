import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import multer from 'multer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(join(__dirname, '../dist')));

// Database setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'seller', 'vendor')),
    avatar TEXT,
    businessId TEXT,
    businessName TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Products table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    unit TEXT NOT NULL,
    category TEXT NOT NULL,
    supplierId INTEGER NOT NULL,
    minOrder INTEGER DEFAULT 1,
    deliveryTime TEXT,
    inStock BOOLEAN DEFAULT 1,
    image TEXT,
    rating REAL DEFAULT 0,
    reviews INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (supplierId) REFERENCES users(id)
  )`);

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orderNumber TEXT UNIQUE NOT NULL,
    vendorId INTEGER NOT NULL,
    supplierId INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
    subtotal REAL NOT NULL,
    tax REAL NOT NULL,
    deliveryFee REAL NOT NULL,
    total REAL NOT NULL,
    deliveryAddress TEXT NOT NULL,
    specialInstructions TEXT,
    paymentMethod TEXT NOT NULL,
    orderDate DATETIME DEFAULT CURRENT_TIMESTAMP,
    deliveryDate DATETIME,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendorId) REFERENCES users(id),
    FOREIGN KEY (supplierId) REFERENCES users(id)
  )`);

  // Order items table
  db.run(`
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      orderId INTEGER NOT NULL,
      productId INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      price REAL NOT NULL,
      unit TEXT DEFAULT 'kg',
      FOREIGN KEY (orderId) REFERENCES orders(id),
      FOREIGN KEY (productId) REFERENCES products(id)
    )
  `);

  // Cart items table
  db.run(`CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    productId INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id),
    FOREIGN KEY (productId) REFERENCES products(id)
  )`);

  // Delivery Partners table
  db.run(`
    CREATE TABLE IF NOT EXISTS delivery_partners (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT,
      vehicle_type TEXT DEFAULT 'bike',
      current_location_lat REAL,
      current_location_lng REAL,
      status TEXT DEFAULT 'available',
      rating REAL DEFAULT 5.0,
      total_deliveries INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Delivery tracking table
  db.run(`
    CREATE TABLE IF NOT EXISTS deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      delivery_partner_id INTEGER,
      pickup_location_lat REAL,
      pickup_location_lng REAL,
      delivery_location_lat REAL,
      delivery_location_lng REAL,
      status TEXT DEFAULT 'pending',
      assigned_at DATETIME,
      pickup_time DATETIME,
      delivery_time DATETIME,
      estimated_delivery_time DATETIME,
      actual_delivery_time DATETIME,
      tracking_number TEXT UNIQUE,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (order_id) REFERENCES orders (id),
      FOREIGN KEY (delivery_partner_id) REFERENCES delivery_partners (id)
    )
  `);

  // Seller locations table
  db.run(`
    CREATE TABLE IF NOT EXISTS seller_locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seller_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      lat REAL NOT NULL,
      lng REAL NOT NULL,
      is_primary BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (seller_id) REFERENCES users (id)
    )
  `);

  // Vendor locations table
  db.run(`
    CREATE TABLE IF NOT EXISTS vendor_locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vendor_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      lat REAL NOT NULL,
      lng REAL NOT NULL,
      is_primary BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (vendor_id) REFERENCES users (id)
    )
  `);

  // Insert sample data
  insertSampleData();
}

// Insert sample data
function insertSampleData() {
  // Check if sample data already exists
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (err) {
      console.error('Error checking sample data:', err);
      return;
    }
    
    if (row.count > 0) {
      console.log('Sample data already exists');
      return;
    }

    // Insert sample users
    const sampleUsers = [
      {
        email: 'admin@streetsmart.com',
        password: bcrypt.hashSync('password', 10),
        name: 'Admin User',
        role: 'admin',
        avatar: 'https://images.pexels.com/photos/3764578/pexels-photo-3764578.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop'
      },
      {
        email: 'seller@example.com',
        password: bcrypt.hashSync('password', 10),
        name: 'Green Valley Farms',
        role: 'seller',
        businessId: 'SUP001',
        businessName: 'Green Valley Farms',
        avatar: 'https://images.pexels.com/photos/3785079/pexels-photo-3785079.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop'
      },
      {
        email: 'freshfood@example.com',
        password: bcrypt.hashSync('password', 10),
        name: 'Fresh Food Suppliers',
        role: 'seller',
        businessId: 'SUP002',
        businessName: 'Fresh Food Suppliers',
        avatar: 'https://images.pexels.com/photos/3785079/pexels-photo-3785079.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop'
      },
      {
        email: 'organic@example.com',
        password: bcrypt.hashSync('password', 10),
        name: 'Organic Harvest Co.',
        role: 'seller',
        businessId: 'SUP003',
        businessName: 'Organic Harvest Co.',
        avatar: 'https://images.pexels.com/photos/3785079/pexels-photo-3785079.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop'
      },
      {
        email: 'vendor@example.com',
        password: bcrypt.hashSync('password', 10),
        name: 'Green Valley',
        role: 'vendor',
        businessId: 'VEN001',
        businessName: 'Green Valley',
        avatar: 'https://images.pexels.com/photos/3764578/pexels-photo-3764578.jpeg?auto=compress&cs=tinysrgb&w=150&h=150&fit=crop'
      }
    ];

    sampleUsers.forEach(user => {
      db.run(
        'INSERT INTO users (email, password, name, role, avatar, businessId, businessName) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [user.email, user.password, user.name, user.role, user.avatar, user.businessId, user.businessName],
        function(err) {
          if (err) {
            console.error('Error inserting user:', err);
          } else {
            console.log('Inserted user:', user.email);
          }
        }
      );
    });

    // Insert sample products
    const sampleProducts = [
      // Green Valley Farms products
      {
        name: 'Premium Ground Beef',
        supplierId: 2,
        price: 450,
        unit: 'kg',
        description: 'High-quality ground beef from grass-fed cattle',
        image: 'https://images.unsplash.com/photo-1544025162-d76694265947?w=400',
        category: 'Meat',
        minOrder: 5,
        deliveryTime: '2-3 days',
        inStock: true,
        rating: 4.8,
        reviews: 124,
        location: 'Mumbai',
        distance: '2.5 km'
      },
      {
        name: 'Fresh Tomatoes',
        supplierId: 2,
        price: 80,
        unit: 'kg',
        description: 'Fresh, ripe tomatoes from local farms',
        image: 'https://images.unsplash.com/photo-1546094096-0df4bcaaa337?w=400',
        category: 'Vegetables',
        minOrder: 10,
        deliveryTime: '1-2 days',
        inStock: true,
        rating: 4.5,
        reviews: 89,
        location: 'Delhi',
        distance: '1.8 km'
      },
      {
        name: 'Organic Bananas',
        supplierId: 2,
        price: 120,
        unit: 'dozen',
        description: 'Organic bananas from sustainable farms',
        image: 'https://images.unsplash.com/photo-1571771894821-ce9b6c11b08e?w=400',
        category: 'Fruits',
        minOrder: 5,
        deliveryTime: '1-2 days',
        inStock: true,
        rating: 4.7,
        reviews: 156,
        location: 'Bangalore',
        distance: '3.2 km'
      },
      // Fresh Food Suppliers products
      {
        name: 'Fresh Chicken Breast',
        supplierId: 3,
        price: 380,
        unit: 'kg',
        description: 'Fresh chicken breast from free-range farms',
        image: 'https://images.unsplash.com/photo-1604503468506-a8da13d82791?w=400',
        category: 'Meat',
        minOrder: 3,
        deliveryTime: '1-2 days',
        inStock: true,
        rating: 4.6,
        reviews: 95,
        location: 'Mumbai',
        distance: '1.2 km'
      },
      {
        name: 'Fresh Spinach',
        supplierId: 3,
        price: 45,
        unit: 'kg',
        description: 'Fresh spinach leaves from organic farms',
        image: 'https://images.unsplash.com/photo-1576045057995-568f588f82fb?w=400',
        category: 'Vegetables',
        minOrder: 8,
        deliveryTime: 'Same day',
        inStock: true,
        rating: 4.9,
        reviews: 67,
        location: 'Delhi',
        distance: '0.8 km'
      },
      {
        name: 'Fresh Oranges',
        supplierId: 3,
        price: 90,
        unit: 'dozen',
        description: 'Sweet and juicy oranges from local orchards',
        image: 'https://images.unsplash.com/photo-1547514701-42782101795e?w=400',
        category: 'Fruits',
        minOrder: 4,
        deliveryTime: '1-2 days',
        inStock: true,
        rating: 4.4,
        reviews: 112,
        location: 'Bangalore',
        distance: '2.1 km'
      },
      // Organic Harvest Co. products
      {
        name: 'Organic Quinoa',
        supplierId: 4,
        price: 180,
        unit: 'kg',
        description: 'Premium organic quinoa from sustainable farms',
        image: 'https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400',
        category: 'Grains',
        minOrder: 2,
        deliveryTime: '2-3 days',
        inStock: true,
        rating: 4.8,
        reviews: 89,
        location: 'Chennai',
        distance: '3.5 km'
      },
      {
        name: 'Organic Greek Yogurt',
        supplierId: 4,
        price: 120,
        unit: 'liter',
        description: 'Creamy organic Greek yogurt',
        image: 'https://images.unsplash.com/photo-1550583724-b2692b85b150?w=400',
        category: 'Dairy',
        minOrder: 5,
        deliveryTime: 'Same day',
        inStock: true,
        rating: 4.7,
        reviews: 156,
        location: 'Pune',
        distance: '1.8 km'
      },
      {
        name: 'Organic Bell Peppers',
        supplierId: 4,
        price: 75,
        unit: 'kg',
        description: 'Colorful organic bell peppers',
        image: 'https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=400',
        category: 'Vegetables',
        minOrder: 6,
        deliveryTime: '1-2 days',
        inStock: true,
        rating: 4.5,
        reviews: 78,
        location: 'Hyderabad',
        distance: '2.3 km'
      }
    ];

    sampleProducts.forEach(product => {
      db.run(
        'INSERT INTO products (name, description, price, unit, category, supplierId, minOrder, deliveryTime, image, rating, reviews) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [product.name, product.description, product.price, product.unit, product.category, product.supplierId, product.minOrder, product.deliveryTime, product.image, product.rating, product.reviews],
        function(err) {
          if (err) {
            console.error('Error inserting product:', err);
          } else {
            console.log('Inserted product:', product.name);
          }
        }
      );
    });

    // Insert sample delivery partners
    db.run(`
      INSERT OR IGNORE INTO delivery_partners (id, name, phone, email, vehicle_type, current_location_lat, current_location_lng, status, rating, total_deliveries)
      VALUES 
      (1, 'Rajesh Kumar', '+91-9876543210', 'rajesh@delivery.com', 'bike', 23.0225, 72.5714, 'available', 4.8, 156),
      (2, 'Amit Patel', '+91-9876543211', 'amit@delivery.com', 'bike', 23.0225, 72.5714, 'available', 4.9, 203),
      (3, 'Suresh Singh', '+91-9876543212', 'suresh@delivery.com', 'car', 23.0225, 72.5714, 'available', 4.7, 89),
      (4, 'Mohan Sharma', '+91-9876543213', 'mohan@delivery.com', 'bike', 23.0225, 72.5714, 'busy', 4.6, 134),
      (5, 'Ramesh Verma', '+91-9876543214', 'ramesh@delivery.com', 'bike', 23.0225, 72.5714, 'available', 4.5, 78)
    `);

    // Insert sample seller locations
    db.run(`
      INSERT OR IGNORE INTO seller_locations (id, seller_id, name, address, lat, lng, is_primary)
      VALUES 
      (1, 2, 'Green Valley Farms - Main Warehouse', 'Plot 45, Industrial Area, Ahmedabad, Gujarat 380001', 23.0225, 72.5714, 1),
      (2, 2, 'Green Valley Farms - Cold Storage', 'Sector 12, Gandhinagar, Gujarat 382001', 23.2156, 72.6369, 0),
      (3, 3, 'Quality Meats Co. - Processing Unit', 'Industrial Estate, Vadodara, Gujarat 390001', 22.3072, 73.1812, 1),
      (4, 4, 'Spice Masters - Main Facility', 'Export Zone, Surat, Gujarat 395001', 21.1702, 72.8311, 1),
      (5, 5, 'Fresh Dairy Co. - Distribution Center', 'Highway 48, Rajkot, Gujarat 360001', 22.3039, 70.8022, 1)
    `);

    // Insert sample vendor locations
    db.run(`
      INSERT OR IGNORE INTO vendor_locations (id, vendor_id, name, address, lat, lng, is_primary)
      VALUES 
      (1, 3, 'Food Truck - Downtown', 'Law Garden, Ahmedabad, Gujarat 380006', 23.0225, 72.5714, 1),
      (2, 3, 'Food Truck - Airport Area', 'Sardar Vallabhbhai Patel International Airport, Ahmedabad', 23.0711, 72.6346, 0),
      (3, 6, 'Restaurant - City Center', 'CG Road, Ahmedabad, Gujarat 380009', 23.0225, 72.5714, 1),
      (4, 7, 'Catering Service - Office', 'Satellite, Ahmedabad, Gujarat 380015', 23.0225, 72.5714, 1),
      (5, 8, 'Hotel Kitchen - Downtown', 'Navrangpura, Ahmedabad, Gujarat 380009', 23.0225, 72.5714, 1)
    `);
  });
}

// Function to notify suppliers about new orders
function notifySupplier(supplierId, orderDetails) {
  console.log(`🔔 NOTIFICATION SENT TO SUPPLIER ${supplierId}:`);
  console.log(`📦 New Order Received: ${orderDetails.orderNumber}`);
  console.log(`💰 Total Amount: ₹${orderDetails.totalAmount.toFixed(2)}`);
  console.log(`📋 Items: ${orderDetails.itemCount || 1} products`);
  console.log(`📍 Delivery Address: ${orderDetails.deliveryAddress}`);
  console.log(`💳 Payment Method: ${orderDetails.paymentMethod}`);
  console.log(`📝 Special Instructions: ${orderDetails.specialInstructions}`);
  console.log(`⏰ Order Date: ${orderDetails.orderDate}`);
  console.log('---');
}

// Function to send order confirmation to vendor
function notifyVendor(vendorId, orderDetails) {
  console.log(`📧 ORDER CONFIRMATION SENT TO VENDOR ${vendorId}:`);
  console.log(`✅ Order Placed Successfully: ${orderDetails.orderNumber}`);
  console.log(`💰 Total Amount: ₹${orderDetails.totalAmount.toFixed(2)}`);
  console.log(`📦 Orders sent to ${orderDetails.supplierCount} suppliers`);
  console.log(`📅 Expected Delivery: ${orderDetails.expectedDelivery}`);
  console.log('---');
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role, businessName, businessId } = req.body;

    // Add validation for required fields
    if (!email || !password || !name || !role) {
      console.log('Registration attempt with missing required fields:', { 
        email: !!email, 
        password: !!password, 
        name: !!name, 
        role: !!role 
      });
      return res.status(400).json({ error: 'Email, password, name, and role are required' });
    }

    // Validate role
    if (!['seller', 'vendor'].includes(role)) {
      console.log('Invalid role provided:', role);
      return res.status(400).json({ error: 'Role must be either seller or vendor' });
    }

    console.log('Registration attempt for email:', email, 'role:', role);

    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error('Database error during registration check:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (row) {
        console.log('User already exists for email:', email);
        return res.status(400).json({ error: 'User already exists' });
      }

      try {
        console.log('Hashing password...');
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        console.log('Creating new user...');
        // Insert new user
        db.run(
          'INSERT INTO users (email, password, name, role, businessName, businessId) VALUES (?, ?, ?, ?, ?, ?)',
          [email, hashedPassword, name, role, businessName || null, businessId || null],
          function(err) {
            if (err) {
              console.error('Error creating user:', err);
              return res.status(500).json({ error: 'Error creating user' });
            }

            console.log('User created successfully, generating token...');

            // Generate JWT token
            const token = jwt.sign(
              { id: parseInt(this.lastID), email, role },
              JWT_SECRET,
              { expiresIn: '24h' }
            );

            console.log('Registration successful for user:', email, 'role:', role);

            res.json({
              token,
              user: {
                id: this.lastID,
                email,
                name,
                role,
                businessName: businessName || null,
                businessId: businessId || null
              }
            });
          }
        );
      } catch (hashError) {
        console.error('Password hashing error:', hashError);
        return res.status(500).json({ error: 'Registration failed' });
      }
    });
  } catch (error) {
    console.error('Server error during registration:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Add validation for required fields
    if (!email || !password) {
      console.log('Login attempt with missing credentials:', { email: !!email, password: !!password });
      return res.status(400).json({ error: 'Email and password are required' });
    }

    console.log('Login attempt for email:', email);

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        console.log('User not found for email:', email);
        return res.status(400).json({ error: 'Invalid email or password' });
      }

      console.log('User found, verifying password...');
      
      try {
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          console.log('Invalid password for user:', email);
          return res.status(400).json({ error: 'Invalid email or password' });
        }

        console.log('Password verified, generating token...');

        // Generate JWT token
        const token = jwt.sign(
          { id: parseInt(user.id), email: user.email, role: user.role },
          JWT_SECRET,
          { expiresIn: '24h' }
        );

        console.log('Login successful for user:', email, 'role:', user.role);

        res.json({
          token,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            avatar: user.avatar,
            businessId: user.businessId,
            businessName: user.businessName
          }
        });
      } catch (bcryptError) {
        console.error('Bcrypt error:', bcryptError);
        return res.status(500).json({ error: 'Authentication error' });
      }
    });
  } catch (error) {
    console.error('Server error during login:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/google', async (req, res) => {
  const { email, name, avatar } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (user) {
      // User exists, return user and token
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
      return res.json({ token, user });
    } else {
      // Create new user (default role: vendor)
      db.run(
        'INSERT INTO users (email, name, role, avatar) VALUES (?, ?, ?, ?)',
        [email, name, 'vendor', avatar],
        function (err) {
          if (err) return res.status(500).json({ error: "Error creating user" });
          const token = jwt.sign({ id: this.lastID, email, role: 'vendor' }, JWT_SECRET, { expiresIn: '24h' });
          res.json({
            token,
            user: {
              id: this.lastID,
              email,
              name,
              role: 'vendor',
              avatar
            }
          });
        }
      );
    }
  });
});

// Products routes
app.get('/api/products', (req, res) => {
  const { category, search, supplierId } = req.query;
  let query = `
    SELECT p.*, u.name as supplierName, u.avatar as supplierImage 
    FROM products p 
    JOIN users u ON p.supplierId = u.id 
    WHERE 1=1
  `;
  const params = [];

  if (category && category !== 'all') {
    query += ' AND p.category = ?';
    params.push(category);
  }

  if (search) {
    query += ' AND (p.name LIKE ? OR p.description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  if (supplierId) {
    query += ' AND p.supplierId = ?';
    params.push(supplierId);
  }

  query += ' ORDER BY p.createdAt DESC';

  db.all(query, params, (err, products) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(products);
  });
});

app.get('/api/products/:id', (req, res) => {
  const { id } = req.params;
  
  db.get(`
    SELECT p.*, u.name as supplierName, u.avatar as supplierImage 
    FROM products p 
    JOIN users u ON p.supplierId = u.id 
    WHERE p.id = ?
  `, [id], (err, product) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  });
});

// Suppliers routes
app.get('/api/suppliers', (req, res) => {
  const query = `
    SELECT 
      u.id,
      u.name as supplierName,
      u.businessName,
      u.avatar as supplierImage,
      COUNT(p.id) as totalProducts,
      AVG(p.rating) as averageRating,
      COUNT(p.reviews) as totalReviews
    FROM users u 
    LEFT JOIN products p ON u.id = p.supplierId 
    WHERE u.role = 'seller'
    GROUP BY u.id, u.name, u.businessName, u.avatar
    ORDER BY averageRating DESC
  `;

  db.all(query, [], (err, suppliers) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(suppliers);
  });
});

app.get('/api/suppliers/:id', (req, res) => {
  const { id } = req.params;
  
  db.get(`
    SELECT 
      u.id,
      u.name as supplierName,
      u.businessName,
      u.avatar as supplierImage,
      u.email,
      COUNT(p.id) as totalProducts,
      AVG(p.rating) as averageRating,
      COUNT(p.reviews) as totalReviews
    FROM users u 
    LEFT JOIN products p ON u.id = p.supplierId 
    WHERE u.id = ? AND u.role = 'seller'
    GROUP BY u.id, u.name, u.businessName, u.avatar, u.email
  `, [id], (err, supplier) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!supplier) {
      return res.status(404).json({ error: 'Supplier not found' });
    }
    res.json(supplier);
  });
});

// Cart routes
app.get('/api/cart', authenticateToken, (req, res) => {
  const userId = parseInt(req.user.id);
  
  db.all(`
    SELECT ci.*, p.name, p.price, p.unit, p.image, p.minOrder, p.deliveryTime, p.supplierId, u.name as supplierName
    FROM cart_items ci
    JOIN products p ON ci.productId = p.id
    JOIN users u ON p.supplierId = u.id
    WHERE ci.userId = ?
  `, [userId], (err, cartItems) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(cartItems);
  });
});

app.post('/api/cart', authenticateToken, (req, res) => {
  const userId = parseInt(req.user.id);
  const { productId, quantity } = req.body;

  // Check if item already in cart
  db.get('SELECT id FROM cart_items WHERE userId = ? AND productId = ?', [userId, productId], (err, existing) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (existing) {
      // Update quantity
      db.run('UPDATE cart_items SET quantity = quantity + ? WHERE userId = ? AND productId = ?', 
        [quantity, userId, productId], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Cart updated' });
      });
    } else {
      // Add new item
      db.run('INSERT INTO cart_items (userId, productId, quantity) VALUES (?, ?, ?)', 
        [userId, productId, quantity], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Item added to cart' });
      });
    }
  });
});

app.put('/api/cart/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  const userId = parseInt(req.user.id);

  db.run('UPDATE cart_items SET quantity = ? WHERE id = ? AND userId = ?', 
    [quantity, id, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    res.json({ message: 'Cart updated' });
  });
});

app.delete('/api/cart/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = parseInt(req.user.id);

  db.run('DELETE FROM cart_items WHERE id = ? AND userId = ?', [id, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    res.json({ message: 'Item removed from cart' });
  });
});

// Clear entire cart for a user
app.delete('/api/cart', authenticateToken, (req, res) => {
  const userId = parseInt(req.user.id);

  db.run('DELETE FROM cart_items WHERE userId = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'Cart cleared successfully' });
  });
});

// Orders routes
app.get('/api/orders', authenticateToken, (req, res) => {
  const userId = parseInt(req.user.id);
  const { role } = req.user;
  
  let query = `
    SELECT o.*, u.name as vendorName, s.name as supplierName
    FROM orders o
    JOIN users u ON o.vendorId = u.id
    JOIN users s ON o.supplierId = s.id
    WHERE 1=1
  `;
  const params = [];

  if (role === 'vendor') {
    query += ' AND o.vendorId = ?';
    params.push(userId);
  } else if (role === 'seller') {
    query += ' AND o.supplierId = ?';
    params.push(userId);
  }

  query += ' ORDER BY o.createdAt DESC';

  db.all(query, params, (err, orders) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(orders);
  });
});

// Get order items for a specific order
app.get('/api/orders/:orderId/items', authenticateToken, (req, res) => {
  const { orderId } = req.params;
  const userId = parseInt(req.user.id);
  const { role } = req.user;

  // First verify the user has access to this order
  let accessQuery = `
    SELECT id FROM orders 
    WHERE id = ? AND (
      ${role === 'vendor' ? 'vendorId = ?' : 'supplierId = ?'}
    )
  `;
  const accessParams = [orderId, userId];

  db.get(accessQuery, accessParams, (err, order) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!order) {
      return res.status(404).json({ error: 'Order not found or access denied' });
    }

    // Get order items with product details
    const query = `
      SELECT oi.*, p.name as productName, p.image as productImage
      FROM order_items oi
      JOIN products p ON oi.productId = p.id
      WHERE oi.orderId = ?
    `;

    db.all(query, [orderId], (err, items) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(items);
    });
  });
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const userId = parseInt(req.user.id);
  const { items, deliveryAddress, paymentMethod, specialInstructions } = req.body;

  console.log('🔍 Order creation request:', {
    userId,
    items,
    deliveryAddress,
    paymentMethod,
    specialInstructions
  });

  // Group items by supplier
  const ordersBySupplier = {};
  items.forEach(item => {
    const supplierId = parseInt(item.supplierId);
    console.log(`📦 Processing item: ${item.productId}, supplierId: ${item.supplierId} -> ${supplierId}`);
    if (!ordersBySupplier[supplierId]) {
      ordersBySupplier[supplierId] = [];
    }
    ordersBySupplier[supplierId].push(item);
  });

  console.log('📋 Orders grouped by supplier:', ordersBySupplier);

  let totalOrderAmount = 0;

  // Create orders for each supplier
  const createdOrders = [];
  
  for (const [supplierId, supplierItems] of Object.entries(ordersBySupplier)) {
    const subtotal = supplierItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const tax = subtotal * 0.18; // Updated to 18% GST
    const deliveryFee = subtotal >= 1000 ? 0 : 100; // Updated to ₹1000 threshold
    const total = subtotal + tax + deliveryFee;
    totalOrderAmount += total;

    const orderNumber = `ORD-${Date.now()}-${supplierId}`;

    await new Promise((resolve, reject) => {
      db.run(`
        INSERT INTO orders (orderNumber, vendorId, supplierId, status, subtotal, tax, deliveryFee, total, deliveryAddress, paymentMethod, specialInstructions)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [orderNumber, userId, parseInt(supplierId), 'pending', subtotal, tax, deliveryFee, total, deliveryAddress, paymentMethod, specialInstructions || ''], function(err) {
        if (err) {
          reject(err);
          return;
        }

        const orderId = this.lastID;

        // Insert order items
        supplierItems.forEach(item => {
          db.run(`
            INSERT INTO order_items (orderId, productId, quantity, price, unit)
            VALUES (?, ?, ?, ?, ?)
          `, [orderId, item.productId, item.quantity, item.price, item.unit]);
        });

        const orderDetails = {
          orderNumber,
          totalAmount: total,
          supplierCount: Object.keys(ordersBySupplier).length,
          itemCount: supplierItems.length,
          deliveryAddress,
          paymentMethod,
          specialInstructions: specialInstructions || 'No special instructions',
          orderDate: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
        };

        notifySupplier(parseInt(supplierId), orderDetails);

        createdOrders.push({
          id: orderId,
          orderNumber,
          supplierId: parseInt(supplierId),
          total
        });

        resolve();
      });
    });
  }

  // Clear cart
  db.run('DELETE FROM cart_items WHERE userId = ?', [userId]);

  // Notify vendor about order confirmation
  const vendorOrderDetails = {
    orderNumber: `ORD-${Date.now()}`,
    totalAmount: totalOrderAmount,
    supplierCount: Object.keys(ordersBySupplier).length,
    expectedDelivery: '2-5 business days',
    deliveryAddress: deliveryAddress,
    paymentMethod: paymentMethod,
    specialInstructions: specialInstructions || 'No special instructions',
    orderDate: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
  };
  notifyVendor(userId, vendorOrderDetails);

  // Auto-assign delivery partners to orders
  const availablePartners = await new Promise((resolve, reject) => {
    db.all(`
      SELECT * FROM delivery_partners 
      WHERE status = 'available'
      ORDER BY rating DESC, total_deliveries ASC
      LIMIT 1
    `, [], (err, partners) => {
      if (err) reject(err);
      else resolve(partners);
    });
  });

  if (availablePartners && availablePartners.length > 0) {
    const selectedPartner = availablePartners[0];
    
    // Update partner status to busy
    db.run(`
      UPDATE delivery_partners 
      SET status = 'busy' 
      WHERE id = ?
    `, [selectedPartner.id]);

    // Create delivery records for each order
    for (const createdOrder of createdOrders) {
      const trackingNumber = `TRK-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const estimatedDeliveryTime = new Date(Date.now() + (2 + Math.random() * 2) * 60 * 60 * 1000);

      // Get seller and vendor locations
      db.get(`
        SELECT * FROM seller_locations 
        WHERE seller_id = ? AND is_primary = 1
      `, [createdOrder.supplierId], (err, sellerLocation) => {
        if (!err && sellerLocation) {
          db.get(`
            SELECT * FROM vendor_locations 
            WHERE vendor_id = ? AND is_primary = 1
          `, [userId], (err, vendorLocation) => {
            if (!err && vendorLocation) {
              db.run(`
                INSERT INTO deliveries (
                  order_id, delivery_partner_id, pickup_location_lat, pickup_location_lng,
                  delivery_location_lat, delivery_location_lng, status, assigned_at,
                  estimated_delivery_time, tracking_number
                ) VALUES (?, ?, ?, ?, ?, ?, 'assigned', CURRENT_TIMESTAMP, ?, ?)
              `, [
                createdOrder.id, selectedPartner.id, sellerLocation.lat, sellerLocation.lng,
                vendorLocation.lat, vendorLocation.lng, estimatedDeliveryTime.toISOString(), trackingNumber
              ]);
            }
          });
        }
      });
    }
  }

  res.json({
    success: true,
    message: 'Orders created successfully and suppliers notified',
    orders: createdOrders,
    totalAmount: totalOrderAmount,
    supplierCount: Object.keys(ordersBySupplier).length
  });
});

// Update order status
app.put('/api/orders/:orderId', authenticateToken, (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  const userId = parseInt(req.user.id); // Convert to integer
  const { role } = req.user;

  console.log('Updating order status:', { orderId, status, userId, role });

  // Validate status
  const validStatuses = ['pending', 'accepted', 'processing', 'ready', 'shipped', 'delivered', 'cancelled'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  // Check if user has access to this order
  let accessQuery = `
    SELECT id FROM orders 
    WHERE id = ? AND (
      ${role === 'vendor' ? 'vendorId = ?' : 'supplierId = ?'}
    )
  `;
  const accessParams = [orderId, userId];

  console.log('Checking access with query:', accessQuery, 'params:', accessParams);

  db.get(accessQuery, accessParams, (err, order) => {
    if (err) {
      console.error('Database error checking access:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!order) {
      console.log('Order not found or access denied for orderId:', orderId, 'userId:', userId, 'role:', role);
      return res.status(404).json({ error: 'Order not found or access denied' });
    }

    console.log('Order found, updating status to:', status);

    // Update order status
    db.run('UPDATE orders SET status = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?', [status, orderId], function(err) {
      if (err) {
        console.error('Database error updating status:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      console.log('Order status updated successfully');
      res.json({ 
        success: true, 
        message: 'Order status updated successfully',
        orderId: orderId,
        status: status
      });
    });
  });
});

// Notifications routes
app.get('/api/notifications', authenticateToken, (req, res) => {
  const userId = parseInt(req.user.id);
  const { role } = req.user;
  
  if (role !== 'seller') {
    return res.status(403).json({ error: 'Supplier access required' });
  }

  // Get recent orders for this supplier
  const query = `
    SELECT o.*, u.name as vendorName, u.email as vendorEmail
    FROM orders o
    JOIN users u ON o.vendorId = u.id
    WHERE o.supplierId = ? AND o.status = 'pending'
    ORDER BY o.createdAt DESC
    LIMIT 10
  `;

  db.all(query, [userId], (err, notifications) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(notifications);
  });
});

// Users routes
app.get('/api/users', authenticateToken, (req, res) => {
  const { role } = req.user;
  
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  db.all('SELECT id, email, name, role, createdAt FROM users ORDER BY createdAt DESC', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(users);
  });
});

// Delivery Partner APIs
app.get('/api/delivery-partners', authenticateToken, (req, res) => {
  db.all(`
    SELECT * FROM delivery_partners 
    ORDER BY status ASC, rating DESC
  `, [], (err, partners) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(partners);
  });
});

app.get('/api/delivery-partners/available', authenticateToken, (req, res) => {
  db.all(`
    SELECT * FROM delivery_partners 
    WHERE status = 'available'
    ORDER BY rating DESC, total_deliveries ASC
  `, [], (err, partners) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(partners);
  });
});

// Assign delivery partner to order
app.post('/api/deliveries/assign', authenticateToken, (req, res) => {
  const { orderId, deliveryPartnerId } = req.body;
  
  if (!orderId || !deliveryPartnerId) {
    return res.status(400).json({ error: 'Order ID and Delivery Partner ID are required' });
  }

  // Get order details
  db.get(`
    SELECT o.*, u.name as vendorName, s.name as supplierName
    FROM orders o
    JOIN users u ON o.vendorId = u.id
    JOIN users s ON o.supplierId = s.id
    WHERE o.id = ?
  `, [orderId], (err, order) => {
    if (err || !order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Get seller location
    db.get(`
      SELECT * FROM seller_locations 
      WHERE seller_id = ? AND is_primary = 1
    `, [order.supplierId], (err, sellerLocation) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      // Get vendor location
      db.get(`
        SELECT * FROM vendor_locations 
        WHERE vendor_id = ? AND is_primary = 1
      `, [order.vendorId], (err, vendorLocation) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Generate tracking number
        const trackingNumber = `TRK-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        // Calculate estimated delivery time (2-4 hours from now)
        const estimatedDeliveryTime = new Date(Date.now() + (2 + Math.random() * 2) * 60 * 60 * 1000);

        // Create delivery record
        db.run(`
          INSERT INTO deliveries (
            order_id, delivery_partner_id, pickup_location_lat, pickup_location_lng,
            delivery_location_lat, delivery_location_lng, status, assigned_at,
            estimated_delivery_time, tracking_number
          ) VALUES (?, ?, ?, ?, ?, ?, 'assigned', CURRENT_TIMESTAMP, ?, ?)
        `, [
          orderId, deliveryPartnerId, sellerLocation.lat, sellerLocation.lng,
          vendorLocation.lat, vendorLocation.lng, estimatedDeliveryTime.toISOString(), trackingNumber
        ], function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          // Update delivery partner status
          db.run(`
            UPDATE delivery_partners 
            SET status = 'busy' 
            WHERE id = ?
          `, [deliveryPartnerId]);

          // Update order status
          db.run(`
            UPDATE orders 
            SET status = 'in_transit' 
            WHERE id = ?
          `, [orderId]);

          res.json({
            success: true,
            message: 'Delivery partner assigned successfully',
            trackingNumber,
            estimatedDeliveryTime: estimatedDeliveryTime.toISOString(),
            pickupLocation: {
              name: sellerLocation.name,
              address: sellerLocation.address,
              lat: sellerLocation.lat,
              lng: sellerLocation.lng
            },
            deliveryLocation: {
              name: vendorLocation.name,
              address: vendorLocation.address,
              lat: vendorLocation.lat,
              lng: vendorLocation.lng
            }
          });
        });
      });
    });
  });
});

// Update delivery status
app.put('/api/deliveries/:deliveryId/status', authenticateToken, (req, res) => {
  const { deliveryId } = req.params;
  const { status, notes } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status is required' });
  }

  let updateQuery = `UPDATE deliveries SET status = ?`;
  let params = [status];

  if (status === 'picked_up') {
    updateQuery += `, pickup_time = CURRENT_TIMESTAMP`;
  } else if (status === 'delivered') {
    updateQuery += `, delivery_time = CURRENT_TIMESTAMP, actual_delivery_time = CURRENT_TIMESTAMP`;
  }

  if (notes) {
    updateQuery += `, notes = ?`;
    params.push(notes);
  }

  updateQuery += ` WHERE id = ?`;
  params.push(deliveryId);

  db.run(updateQuery, params, function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Delivery not found' });
    }

    // If delivered, update order status and delivery partner
    if (status === 'delivered') {
      db.run(`
        UPDATE orders SET status = 'delivered' 
        WHERE id = (SELECT order_id FROM deliveries WHERE id = ?)
      `, [deliveryId]);

      db.run(`
        UPDATE delivery_partners 
        SET status = 'available', total_deliveries = total_deliveries + 1
        WHERE id = (SELECT delivery_partner_id FROM deliveries WHERE id = ?)
      `, [deliveryId]);
    }

    res.json({
      success: true,
      message: `Delivery status updated to ${status}`
    });
  });
});

// Get delivery tracking
app.get('/api/deliveries/tracking/:trackingNumber', (req, res) => {
  const { trackingNumber } = req.params;

  db.get(`
    SELECT d.*, o.orderNumber, o.total, o.deliveryAddress,
           dp.name as deliveryPartnerName, dp.phone as deliveryPartnerPhone,
           dp.vehicle_type as vehicleType, dp.rating as partnerRating,
           sl.name as pickupLocationName, sl.address as pickupAddress,
           vl.name as deliveryLocationName, vl.address as deliveryAddress
    FROM deliveries d
    JOIN orders o ON d.order_id = o.id
    JOIN delivery_partners dp ON d.delivery_partner_id = dp.id
    JOIN seller_locations sl ON o.supplierId = sl.seller_id AND sl.is_primary = 1
    JOIN vendor_locations vl ON o.vendorId = vl.vendor_id AND vl.is_primary = 1
    WHERE d.tracking_number = ?
  `, [trackingNumber], (err, delivery) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }

    // Calculate delivery progress
    let progress = 0;
    let statusText = '';
    
    switch (delivery.status) {
      case 'pending':
        progress = 0;
        statusText = 'Order confirmed, waiting for delivery partner';
        break;
      case 'assigned':
        progress = 25;
        statusText = 'Delivery partner assigned';
        break;
      case 'picked_up':
        progress = 50;
        statusText = 'Order picked up from seller';
        break;
      case 'in_transit':
        progress = 75;
        statusText = 'Order in transit to vendor';
        break;
      case 'delivered':
        progress = 100;
        statusText = 'Order delivered successfully';
        break;
      default:
        progress = 0;
        statusText = 'Unknown status';
    }

    res.json({
      ...delivery,
      progress,
      statusText
    });
  });
});

// Get all deliveries for admin/seller
app.get('/api/deliveries', authenticateToken, (req, res) => {
  const { status, deliveryPartnerId } = req.query;
  
  let query = `
    SELECT d.*, o.orderNumber, o.total, o.deliveryAddress,
           dp.name as deliveryPartnerName, dp.phone as deliveryPartnerPhone,
           dp.vehicle_type as vehicleType, dp.rating as partnerRating
    FROM deliveries d
    JOIN orders o ON d.order_id = o.id
    JOIN delivery_partners dp ON d.delivery_partner_id = dp.id
  `;
  
  let params = [];
  let conditions = [];
  
  if (status) {
    conditions.push('d.status = ?');
    params.push(status);
  }
  
  if (deliveryPartnerId) {
    conditions.push('d.delivery_partner_id = ?');
    params.push(deliveryPartnerId);
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY d.created_at DESC';

  db.all(query, params, (err, deliveries) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(deliveries);
  });
});

// Update delivery partner location
app.put('/api/delivery-partners/:partnerId/location', authenticateToken, (req, res) => {
  const { partnerId } = req.params;
  const { lat, lng } = req.body;

  if (!lat || !lng) {
    return res.status(400).json({ error: 'Latitude and longitude are required' });
  }

  db.run(`
    UPDATE delivery_partners 
    SET current_location_lat = ?, current_location_lng = ?
    WHERE id = ?
  `, [lat, lng, partnerId], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Delivery partner not found' });
    }

    res.json({
      success: true,
      message: 'Location updated successfully'
    });
  });
});

// Get seller locations
app.get('/api/seller-locations/:sellerId', authenticateToken, (req, res) => {
  const { sellerId } = req.params;

  db.all(`
    SELECT * FROM seller_locations 
    WHERE seller_id = ?
    ORDER BY is_primary DESC, name ASC
  `, [sellerId], (err, locations) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(locations);
  });
});

// Get vendor locations
app.get('/api/vendor-locations/:vendorId', authenticateToken, (req, res) => {
  const { vendorId } = req.params;

  db.all(`
    SELECT * FROM vendor_locations 
    WHERE vendor_id = ?
    ORDER BY is_primary DESC, name ASC
  `, [vendorId], (err, locations) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(locations);
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, '../dist/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 