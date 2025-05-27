// server.js

// Carregar variáveis de ambiente do arquivo .env
require('dotenv').config();

// Importações dos módulos necessários
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Para chamadas às APIs de pagamento
const validator = require('validator'); // Para validação de dados, como número de telefone

// Inicialização do aplicativo Express
const app = express();

// Configurações de Middleware
app.use(cors()); // Habilita CORS para permitir requisições de diferentes origens (seu front-end)
app.use(express.json()); // Habilita o parsing de JSON no corpo das requisições
app.use(express.urlencoded({ extended: true })); // Habilita o parsing de dados de formulário URL-encoded

// Conexão com o Banco de Dados MongoDB
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Conectado ao MongoDB com sucesso!');
    // Função para criar admin padrão (será definida depois)
    createDefaultAdmin();
})
.catch(err => {
    console.error('Erro ao conectar ao MongoDB:', err.message);
    process.exit(1); // Encerra o processo se não conseguir conectar ao DB
});

// Variáveis de ambiente para APIs de pagamento
const MPESA_API_URL = process.env.MPESA_API_URL;
const EMOLA_API_URL = process.env.EMOLA_API_URL;
const PAYMENT_WALLET_ID = process.env.PAYMENT_WALLET_ID;
const JWT_SECRET = process.env.JWT_SECRET;

// Definição da porta do servidor
const PORT = process.env.PORT || 3000;

// Removida a declaração duplicada de createDefaultAdmin aqui
// A definição correta virá após os schemas.

console.log("Configuração inicial do server.js carregada.");
// server.js (continuação)

// ============================
// SCHEMAS E MODELS DO MONGODB
// ============================

// -------- ESQUEMA E MODELO DE USUÁRIO (User) --------
const userSchema = new mongoose.Schema({
    phoneNumber: {
        type: String,
        required: [true, "O número de telefone é obrigatório."],
        unique: true,
        validate: [validator.isMobilePhone, "Por favor, insira um número de telefone válido."],
    },
    password: {
        type: String,
        required: [true, "A senha é obrigatória."],
        minlength: [6, "A senha deve ter pelo menos 6 caracteres."],
    },
    isAdmin: {
        type: Boolean,
        default: false,
    },
    registrationDate: {
        type: Date,
        default: Date.now,
    },
});

// Middleware pré-save para criptografar a senha antes de salvar
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Método para comparar senhas
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// -------- ESQUEMA E MODELO DE PRODUTO (Product) --------
const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "O nome do produto é obrigatório."],
        trim: true,
        unique: true, 
    },
    description: {
        type: String,
        required: [true, "A descrição do produto é obrigatória."],
    },
    image: { 
        type: String,
        required: [true, "A imagem do produto é obrigatória."],
    },
    price: {
        type: Number,
        required: [true, "O preço do produto é obrigatório."],
        min: [0, "O preço não pode ser negativo."],
    },
    category: { 
        type: String,
        required: [true, "A categoria do produto é obrigatória."],
    },
    estimatedDeliveryTime: { 
        type: String,
        default: "Máximo 10 minutos",
    },
    isActive: { 
        type: Boolean,
        default: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Product = mongoose.model('Product', productSchema);

// -------- ESQUEMA E MODELO DE PEDIDO (Order) --------
const orderSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true,
    },
    productName: String, 
    productImage: String, 
    quantity: {
        type: Number,
        default: 1,
    },
    totalAmount: {
        type: Number,
        required: true,
    },
    paymentMethod: { 
        type: String,
        enum: ['mpesa', 'emola', 'pending'],
        default: 'pending',
    },
    paymentStatus: { 
        type: String,
        default: 'pending', // pending, paid, failed
    },
    transactionId: { 
        type: String,
    },
    orderDate: {
        type: Date,
        default: Date.now,
    },
    subscriptionDetails: {
        email: { type: String, default: null },
        password: { type: String, default: null },
        status: {
            type: String,
            enum: ['pending_admin_input', 'delivered', 'error_delivering'],
            default: 'pending_admin_input'
        } 
    },
    buyerInfo: { 
        phoneNumber: String,
        name: String,
    }
});

const Order = mongoose.model('Order', orderSchema);


// -------- ESQUEMA E MODELO DE BANNER (Banner) --------
const bannerSchema = new mongoose.Schema({
    title: { 
        type: String,
        trim: true,
    },
    imageUrl: { 
        type: String,
        required: [true, "A URL da imagem do banner é obrigatória."],
    },
    linkUrl: { 
        type: String,
        trim: true,
    },
    type: { 
        type: String,
        enum: ['main', 'promotion'],
        default: 'main',
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Banner = mongoose.model('Banner', bannerSchema);


// -------- ESQUEMA E MODELO DE CRONÔMETRO REGRESSIVO (Countdown) --------
const countdownSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, "O título do cronômetro é obrigatório."],
        trim: true,
    },
    endDate: {
        type: Date,
        required: [true, "A data final do cronômetro é obrigatória."],
    },
    description: { 
        type: String,
        trim: true,
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Countdown = mongoose.model('Countdown', countdownSchema);


// -------- ESQUEMA E MODELO DE PROMOÇÃO (Promotion) --------
const promotionSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, "O título da promoção é obrigatório."],
        trim: true,
    },
    description: {
        type: String,
        required: [true, "A descrição da promoção é obrigatória."],
    },
    bannerOrVideoUrl: { 
        type: String,
        required: [true, "O banner ou vídeo da promoção é obrigatório."],
    },
    isVide: { // Mantido como 'isVide' conforme o original
        type: Boolean,
        default: false, 
    },
    linkUrl: { 
        type: String,
        trim: true,
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    startDate: {
        type: Date,
        default: Date.now,
    },
    endDate: {
        type: Date,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Promotion = mongoose.model('Promotion', promotionSchema);

console.log("Schemas e Models do MongoDB definidos.");

// Agora vamos implementar a função createDefaultAdmin
async function createDefaultAdmin() {
    // A mensagem "Verificando/criando admin padrão..." já foi logada no .then() da conexão do mongoose
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            const adminPhoneNumber = process.env.ADMIN_DEFAULT_PHONE;
            const adminPassword = process.env.ADMIN_DEFAULT_PASSWORD;

            if (!adminPhoneNumber || !adminPassword) {
                console.warn("Variáveis de ambiente ADMIN_DEFAULT_PHONE ou ADMIN_DEFAULT_PASSWORD não definidas. Admin padrão não será criado.");
                return;
            }

            if (!validator.isMobilePhone(adminPhoneNumber.toString(), 'any', { strictMode: false })) {
                console.warn(`Número de telefone do admin padrão ('${adminPhoneNumber}') inválido. Admin padrão não será criado.`);
                return;
            }

            const defaultAdmin = new User({
                phoneNumber: adminPhoneNumber,
                password: adminPassword, 
                isAdmin: true,
            });
            await defaultAdmin.save();
            console.log('Administrador padrão criado com sucesso.');
        } else {
            console.log('Administrador padrão já existe.');
        }
    } catch (error) {
        console.error('Erro ao criar administrador padrão:', error);
    }
}

// ============================
// MIDDLEWARES DE AUTENTICAÇÃO
// ============================

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (token == null) {
        return res.status(401).json({ message: 'Token não fornecido. Acesso não autorizado.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password'); 
        if (!user) {
            return res.status(403).json({ message: 'Usuário não encontrado. Token inválido.' });
        }
        req.user = user; 
        next(); 
    } catch (err) {
        console.error("Erro na verificação do token:", err.message);
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expirado. Por favor, faça login novamente.' });
        }
        return res.status(403).json({ message: 'Token inválido ou malformado.' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        return res.status(403).json({ message: 'Acesso negado. Requer privilégios de administrador.' });
    }
};

console.log("Middlewares de autenticação definidos.");

// ============================
// ROTAS DA API
// ============================

// -------- ROTAS DE AUTENTICAÇÃO (Públicas) --------
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    const { phoneNumber, password } = req.body;
    if (!phoneNumber || !password) return res.status(400).json({ message: 'Número de telefone e senha são obrigatórios.' });
    if (!validator.isMobilePhone(phoneNumber.toString(), 'any', { strictMode: false })) return res.status(400).json({ message: 'Formato de número de telefone inválido.' });
    if (password.length < 6) return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    try {
        const existingUser = await User.findOne({ phoneNumber });
        if (existingUser) return res.status(409).json({ message: 'Este número de telefone já está cadastrado.' });
        const newUser = new User({ phoneNumber, password });
        await newUser.save();
        const token = jwt.sign({ userId: newUser._id, isAdmin: newUser.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', token, user: { id: newUser._id, phoneNumber: newUser.phoneNumber, isAdmin: newUser.isAdmin }});
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro no cadastro:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar usuário.' });
    }
});

authRouter.post('/login', async (req, res) => {
    const { phoneNumber, password } = req.body;
    if (!phoneNumber || !password) return res.status(400).json({ message: 'Número de telefone e senha são obrigatórios.' });
    try {
        const user = await User.findOne({ phoneNumber });
        if (!user) return res.status(401).json({ message: 'Credenciais inválidas. Verifique o número de telefone.' });
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ message: 'Credenciais inválidas. Verifique a senha.' });
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ message: 'Login bem-sucedido!', token, user: { id: user._id, phoneNumber: user.phoneNumber, isAdmin: user.isAdmin }});
    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});
app.use('/api/auth', authRouter);
console.log("Rotas de autenticação (cadastro e login) definidas.");

// -------- ROTAS DE PRODUTOS (Protegidas - Admin para escrita) --------
const productRouter = express.Router();

productRouter.post('/', authenticateToken, isAdmin, async (req, res) => {
    const { name, description, image, price, category, estimatedDeliveryTime, isActive } = req.body; 
    if (!name || !description || !image || price === undefined || !category) return res.status(400).json({ message: 'Todos os campos obrigatórios (nome, descrição, imagem, preço, categoria) devem ser fornecidos.' });
    if (typeof price !== 'number' || price < 0) return res.status(400).json({ message: 'O preço deve ser um número não negativo.' });
    try {
        const existingProduct = await Product.findOne({ name });
        if (existingProduct) return res.status(409).json({ message: `Um produto com o nome '${name}' já existe.` });
        const newProduct = new Product({ name, description, image, price, category, estimatedDeliveryTime: estimatedDeliveryTime || "Máximo 10 minutos", isActive: isActive === undefined ? true : isActive });
        const savedProduct = await newProduct.save();
        res.status(201).json({ message: 'Produto criado com sucesso!', product: savedProduct });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao criar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar produto.' });
    }
});

productRouter.get('/', async (req, res) => {
    try {
        const { activeOnly } = req.query;
        let query = {};
        if (activeOnly === 'true') query.isActive = true;
        const products = await Product.find(query).sort({ createdAt: -1 });
        res.status(200).json(products);
    } catch (error) {
        console.error("Erro ao listar produtos:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar produtos.' });
    }
});

productRouter.get('/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ message: 'Produto não encontrado.' });
        res.status(200).json(product);
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID de produto inválido.' });
        console.error("Erro ao obter produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao obter produto.' });
    }
});

productRouter.put('/:id', authenticateToken, isAdmin, async (req, res) => {
    const { name, description, image, price, category, estimatedDeliveryTime, isActive } = req.body;
    if (price !== undefined && (typeof price !== 'number' || price < 0)) return res.status(400).json({ message: 'O preço deve ser um número não negativo.' });
    if (isActive !== undefined && typeof isActive !== 'boolean') return res.status(400).json({ message: 'O status de ativo (isActive) deve ser um booleano.' });
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ message: 'Produto não encontrado para atualização.' });
        if (name && name !== product.name) {
            const existingProduct = await Product.findOne({ name, _id: { $ne: product._id } });
            if (existingProduct) return res.status(409).json({ message: `Já existe um produto com o nome '${name}'.` });
        }
        if (name !== undefined) product.name = name;
        if (description !== undefined) product.description = description;
        if (image !== undefined) product.image = image;
        if (price !== undefined) product.price = price;
        if (category !== undefined) product.category = category;
        if (estimatedDeliveryTime !== undefined) product.estimatedDeliveryTime = estimatedDeliveryTime;
        if (isActive !== undefined) product.isActive = isActive;
        const updatedProduct = await product.save();
        res.status(200).json({ message: 'Produto atualizado com sucesso!', product: updatedProduct });
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID de produto inválido.' });
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao atualizar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar produto.' });
    }
});

productRouter.delete('/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) return res.status(404).json({ message: 'Produto não encontrado para deletar.' });
        res.status(200).json({ message: 'Produto deletado com sucesso!', productId: req.params.id });
    } catch (error) {
        if (error.kind === 'ObjectId') return res.status(400).json({ message: 'ID de produto inválido.' });
        console.error("Erro ao deletar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar produto.' });
    }
});
app.use('/api/products', productRouter);
console.log("Rotas CRUD para Produtos definidas.");

// -------- ROTAS DO PERFIL DO USUÁRIO (Protegidas - Usuário Logado) --------
const userRouter = express.Router();

userRouter.get('/profile', authenticateToken, async (req, res) => {
    res.status(200).json({ id: req.user._id, phoneNumber: req.user.phoneNumber, registrationDate: req.user.registrationDate, isAdmin: req.user.isAdmin });
});

userRouter.put('/profile', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres.' });
    try {
        const user = await User.findById(req.user._id); 
        if (!user) return res.status(404).json({ message: 'Usuário não encontrado.' });
        if (currentPassword) {
            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) return res.status(401).json({ message: 'Senha atual incorreta.' });
        } else {
            if (!req.user.isAdmin) return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha.' });
        }
        user.password = newPassword; 
        await user.save();
        res.status(200).json({ message: 'Senha atualizada com sucesso.' });
    } catch (error) {
        console.error("Erro ao atualizar perfil do usuário:", error);
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar perfil.' });
    }
});

userRouter.get('/subscriptions', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user._id }).populate('product', 'name image category').sort({ orderDate: -1 }); 
        res.status(200).json(orders);
    } catch (error) {
        console.error("Erro ao buscar histórico de assinaturas:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar histórico de assinaturas.' });
    }
});

userRouter.get('/subscription/:orderId/credentials', authenticateToken, async (req, res) => {
    const { orderId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(orderId)) return res.status(400).json({ message: 'ID do pedido inválido.' });
    try {
        const order = await Order.findOne({ _id: orderId, user: req.user._id });
        if (!order) return res.status(404).json({ message: 'Pedido não encontrado ou não pertence a este usuário.' });
        if (order.subscriptionDetails && order.subscriptionDetails.status === 'delivered') return res.status(200).json({ orderId: order._id, productName: order.productName, email: order.subscriptionDetails.email, password: order.subscriptionDetails.password, });
        else if (order.paymentStatus === 'paid' && order.subscriptionDetails.status === 'pending_admin_input') return res.status(202).json({ orderId: order._id, productName: order.productName, message: "Seus dados da assinatura aparecerão aqui em no máximo 10 minutos. Aguarde.", status: order.subscriptionDetails.status });
        else if (order.paymentStatus !== 'paid') return res.status(402).json({ orderId: order._id, productName: order.productName, message: "O pagamento deste pedido ainda não foi confirmado ou falhou.", status: order.paymentStatus });
        else if (order.subscriptionDetails.status === 'error_delivering') return res.status(500).json({ message: "Ocorreu um erro ao processar os detalhes da sua assinatura. Contacte o suporte.", status: order.subscriptionDetails.status});
        else return res.status(204).json({ message: "Detalhes da assinatura ainda não disponíveis ou houve um erro.", status: order.subscriptionDetails.status }); // Mantido o status original
    } catch (error) {
        console.error("Erro ao buscar credenciais da assinatura:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar credenciais.' });
    }
});
app.use('/api/user', userRouter);
console.log("Rotas do perfil do usuário definidas.");

// ========================================
// ROTAS DO PAINEL ADMINISTRATIVO
// ========================================
const adminRouter = express.Router();
adminRouter.use(authenticateToken, isAdmin);

// -------- GERENCIAMENTO DE BANNERS (Admin) --------
adminRouter.post('/banners', async (req, res) => {
    const { title, imageUrl, linkUrl, type, isActive } = req.body;
    if (!imageUrl || !type) return res.status(400).json({ message: 'URL da imagem e tipo do banner são obrigatórios.' });
    try {
        const newBanner = new Banner({ title, imageUrl, linkUrl, type, isActive });
        await newBanner.save();
        res.status(201).json({ message: 'Banner criado com sucesso!', banner: newBanner });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao criar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar banner.' });
    }
});
adminRouter.get('/banners', async (req, res) => {
    try {
        const banners = await Banner.find().sort({ createdAt: -1 });
        res.status(200).json(banners);
    } catch (error) {
        console.error("Erro ao listar banners:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar banners.' });
    }
});
adminRouter.put('/banners/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de banner inválido.' });
    try {
        const updatedBanner = await Banner.findByIdAndUpdate(id, req.body, { new: true, runValidators: true });
        if (!updatedBanner) return res.status(404).json({ message: 'Banner não encontrado.' });
        res.status(200).json({ message: 'Banner atualizado com sucesso!', banner: updatedBanner });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao atualizar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar banner.' });
    }
});
adminRouter.delete('/banners/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de banner inválido.' });
    try {
        const deletedBanner = await Banner.findByIdAndDelete(id);
        if (!deletedBanner) return res.status(404).json({ message: 'Banner não encontrado.' });
        res.status(200).json({ message: 'Banner deletado com sucesso!', bannerId: id });
    } catch (error) {
        console.error("Erro ao deletar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar banner.' });
    }
});

// -------- GERENCIAMENTO DE COUNTDOWNS (Admin) --------
adminRouter.post('/countdowns', async (req, res) => {
    const { title, endDate, description, isActive } = req.body;
    if (!title || !endDate) return res.status(400).json({ message: 'Título e data final são obrigatórios para o countdown.' });
    try {
        const newCountdown = new Countdown({ title, endDate, description, isActive });
        await newCountdown.save();
        res.status(201).json({ message: 'Countdown criado com sucesso!', countdown: newCountdown });
    } catch (error) {
         if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao criar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar countdown.' });
    }
});
adminRouter.get('/countdowns', async (req, res) => {
    try {
        const countdowns = await Countdown.find().sort({ createdAt: -1 });
        res.status(200).json(countdowns);
    } catch (error) {
        console.error("Erro ao listar countdowns:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar countdowns.' });
    }
});
adminRouter.put('/countdowns/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de countdown inválido.' });
    try {
        const updatedCountdown = await Countdown.findByIdAndUpdate(id, req.body, { new: true, runValidators: true });
        if (!updatedCountdown) return res.status(404).json({ message: 'Countdown não encontrado.' });
        res.status(200).json({ message: 'Countdown atualizado com sucesso!', countdown: updatedCountdown });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao atualizar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar countdown.' });
    }
});
adminRouter.delete('/countdowns/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de countdown inválido.' });
    try {
        const deletedCountdown = await Countdown.findByIdAndDelete(id);
        if (!deletedCountdown) return res.status(404).json({ message: 'Countdown não encontrado.' });
        res.status(200).json({ message: 'Countdown deletado com sucesso!', countdownId: id });
    } catch (error) {
        console.error("Erro ao deletar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar countdown.' });
    }
});

// -------- GERENCIAMENTO DE PROMOÇÕES (Admin) --------
adminRouter.post('/promotions', async (req, res) => {
    const { title, description, bannerOrVideoUrl, isVideo, linkUrl, isActive, startDate, endDate } = req.body; // isVideo aqui
    if (!title || !description || !bannerOrVideoUrl) return res.status(400).json({ message: 'Título, descrição e URL do banner/vídeo são obrigatórios.' });
    try {
        const newPromotion = new Promotion({ title, description, bannerOrVideoUrl, isVide: isVideo, linkUrl, isActive, startDate, endDate }); // isVide no schema
        await newPromotion.save();
        res.status(201).json({ message: 'Promoção criada com sucesso!', promotion: newPromotion });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao criar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar promoção.' });
    }
});
adminRouter.get('/promotions', async (req, res) => {
    try {
        const promotions = await Promotion.find().sort({ createdAt: -1 });
        res.status(200).json(promotions);
    } catch (error) {
        console.error("Erro ao listar promoções:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar promoções.' });
    }
});
adminRouter.put('/promotions/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de promoção inválido.' });
    try {
        const updateData = { ...req.body };
        if (req.body.isVideo !== undefined) { updateData.isVide = req.body.isVideo; delete updateData.isVideo; }
        const updatedPromotion = await Promotion.findByIdAndUpdate(id, updateData, { new: true, runValidators: true });
        if (!updatedPromotion) return res.status(404).json({ message: 'Promoção não encontrada.' });
        res.status(200).json({ message: 'Promoção atualizada com sucesso!', promotion: updatedPromotion });
    } catch (error) {
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        console.error("Erro ao atualizar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar promoção.' });
    }
});
adminRouter.delete('/promotions/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'ID de promoção inválido.' });
    try {
        const deletedPromotion = await Promotion.findByIdAndDelete(id);
        if (!deletedPromotion) return res.status(404).json({ message: 'Promoção não encontrada.' });
        res.status(200).json({ message: 'Promoção deletada com sucesso!', promotionId: id });
    } catch (error) {
        console.error("Erro ao deletar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar promoção.' });
    }
});

// -------- GERENCIAMENTO DE USUÁRIOS (Admin) --------
adminRouter.get('/users', async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ registrationDate: -1 }); 
        res.status(200).json(users);
    } catch (error) {
        console.error("Erro ao listar usuários:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar usuários.' });
    }
});
adminRouter.get('/users/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({ message: 'ID de usuário inválido.' });
    try {
        const user = await User.findById(userId).select('-password');
        if (!user) return res.status(404).json({ message: 'Usuário não encontrado.' });
        const orders = await Order.find({ user: userId }).populate('product', 'name price').sort({ orderDate: -1 });
        res.status(200).json({ user, orders });
    } catch (error) {
        console.error("Erro ao buscar detalhes do usuário:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar detalhes do usuário.' });
    }
});
adminRouter.put('/users/:userId/status', async (req, res) => {
    const { userId } = req.params;
    const { isAdmin } = req.body;
    if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({ message: 'ID de usuário inválido.' });
    if (typeof isAdmin !== 'boolean' && isAdmin !== undefined) return res.status(400).json({ message: 'O status de administrador (isAdmin) deve ser um booleano.' });
    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'Usuário não encontrado.' });
        if (req.user._id.equals(user._id) && user.isAdmin && isAdmin === false) {
             const adminCount = await User.countDocuments({ isAdmin: true });
             if (adminCount <= 1) return res.status(400).json({ message: 'Não é possível remover o status de administrador do único administrador existente.' });
        }
        if (isAdmin !== undefined) user.isAdmin = isAdmin;
        await user.save();
        const updatedUser = await User.findById(userId).select('-password');
        res.status(200).json({ message: 'Status do usuário atualizado com sucesso.', user: updatedUser });
    } catch (error) {
        console.error("Erro ao atualizar status do usuário:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar status do usuário.' });
    }
});

// -------- GERENCIAMENTO DE PEDIDOS E CREDENCIAIS (Admin) --------
adminRouter.get('/orders', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20; 
        const skip = (page - 1) * limit;
        let filter = {};
        if (req.query.paymentStatus) filter.paymentStatus = req.query.paymentStatus;
        if (req.query.credentialStatus) filter['subscriptionDetails.status'] = req.query.credentialStatus;
        const orders = await Order.find(filter).populate('user', 'phoneNumber').populate('product', 'name').sort({ orderDate: -1 }).skip(skip).limit(limit);
        const totalOrders = await Order.countDocuments(filter);
        res.status(200).json({ orders, currentPage: page, totalPages: Math.ceil(totalOrders / limit), totalOrders });
    } catch (error) {
        console.error("Erro ao listar pedidos:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar pedidos.' });
    }
});
adminRouter.get('/orders/:orderId', async (req, res) => {
    const { orderId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(orderId)) return res.status(400).json({ message: 'ID de pedido inválido.' });
    try {
        const order = await Order.findById(orderId).populate('user', 'phoneNumber registrationDate isAdmin').populate('product');
        if (!order) return res.status(404).json({ message: 'Pedido não encontrado.' });
        res.status(200).json(order);
    } catch (error) {
        console.error("Erro ao buscar detalhes do pedido:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar detalhes do pedido.' });
    }
});
adminRouter.put('/orders/:orderId/credentials', async (req, res) => {
    const { orderId } = req.params;
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'E-mail e senha da assinatura são obrigatórios.' });
    if (!mongoose.Types.ObjectId.isValid(orderId)) return res.status(400).json({ message: 'ID do pedido inválido.' });
    try {
        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ message: 'Pedido não encontrado.' });
        if (order.paymentStatus !== 'paid') return res.status(400).json({ message: 'Não é possível adicionar credenciais a um pedido com pagamento pendente ou falhado.' });
        order.subscriptionDetails.email = email;
        order.subscriptionDetails.password = password; 
        order.subscriptionDetails.status = 'delivered';
        await order.save();
        const updatedOrder = await Order.findById(orderId).populate('user', 'phoneNumber').populate('product', 'name');
        res.status(200).json({ message: 'Dados da assinatura atualizados com sucesso!', order: updatedOrder });
    } catch (error) {
        console.error("Erro ao atualizar credenciais do pedido:", error);
        if (error.name === 'ValidationError') return res.status(400).json({ message: Object.values(error.errors).map(val => val.message).join(', ') });
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar credenciais.' });
    }
});

// -------- GERENCIAMENTO DE TEMA (Admin - Placeholder) --------
let currentThemeSettings = { primaryColor: '#E50914', accentColor: '#FFFFFF', season: 'default',};
adminRouter.post('/theme', (req, res) => {
    const { primaryColor, accentColor, season } = req.body;
    if (primaryColor && !validator.isHexColor(primaryColor)) return res.status(400).json({ message: 'Cor primária inválida (deve ser hexadecimal).' });
    if (accentColor && !validator.isHexColor(accentColor)) return res.status(400).json({ message: 'Cor de destaque inválida (deve ser hexadecimal).' });
    if (primaryColor) currentThemeSettings.primaryColor = primaryColor;
    if (accentColor) currentThemeSettings.accentColor = accentColor;
    if (season) currentThemeSettings.season = season; 
    console.log("Configurações de tema atualizadas para:", currentThemeSettings);
    res.status(200).json({ message: 'Configurações de tema atualizadas com sucesso (simulado).', theme: currentThemeSettings });
});
adminRouter.get('/theme', (req, res) => {
    res.status(200).json(currentThemeSettings);
});
app.use('/api/admin', adminRouter);
app.get('/api/theme', (req, res) => { 
    res.status(200).json(currentThemeSettings);
});
console.log("Rotas do painel administrativo definidas.");

// ============================
// ROTAS DE PAGAMENTO
// ============================
const paymentRouter = express.Router();
paymentRouter.use(authenticateToken);

paymentRouter.post('/initiate', async (req, res) => {
    const { productId, paymentMethod, buyerPhoneNumber, buyerName } = req.body;
    const userId = req.user._id; 

    if (!productId || !paymentMethod || !buyerPhoneNumber || !buyerName) {
        return res.status(400).json({ message: 'ID do produto, método de pagamento, número de telefone do pagador e nome do pagador são obrigatórios.' });
    }
    if (!['mpesa', 'emola'].includes(paymentMethod.toLowerCase())) {
        return res.status(400).json({ message: 'Método de pagamento inválido. Aceitos: mpesa, emola.' });
    }
    if (!validator.isMobilePhone(buyerPhoneNumber.toString(), 'any', { strictMode: false })) {
        return res.status(400).json({ message: 'Formato de número de telefone do pagador inválido.' });
    }

    try {
        const product = await Product.findById(productId);
        if (!product || !product.isActive) {
            return res.status(404).json({ message: 'Produto não encontrado ou indisponível.' });
        }
        const amount = product.price;
        const newOrder = new Order({
            user: userId,
            product: productId,
            productName: product.name, 
            productImage: product.image, 
            totalAmount: amount,
            paymentMethod: paymentMethod.toLowerCase(),
            paymentStatus: 'pending', 
            buyerInfo: { phoneNumber: buyerPhoneNumber, name: buyerName, },
            subscriptionDetails: { email: null, password: null, status: 'pending_admin_input' }
        });
        await newOrder.save();

        const paymentApiUrl = paymentMethod.toLowerCase() === 'mpesa' ? MPESA_API_URL : EMOLA_API_URL;
        if (!paymentApiUrl) {
            console.error(`URL da API para ${paymentMethod} não está definida nas variáveis de ambiente.`);
            newOrder.paymentStatus = 'failed';
            newOrder.transactionId = `Configuração de API de ${paymentMethod} ausente.`;
            await newOrder.save();
            return res.status(500).json({
                success: false,
                message: `Erro de configuração do servidor para ${paymentMethod}. Por favor, contacte o suporte.`
            });
        }
        
        const paymentPayload = {
            carteira: PAYMENT_WALLET_ID,
            numero: buyerPhoneNumber,
            "quem comprou": buyerName, 
            valor: amount.toString(), 
        };

        console.log(`Iniciando pagamento para pedido ${newOrder._id} via ${paymentMethod} com payload:`, paymentPayload);

        axios.post(paymentApiUrl, paymentPayload, {
            headers: { 'Content-Type': 'application/json' },
            validateStatus: (status) => status >= 200 && status < 500, // Processar respostas 2xx e 4xx no .then()
        })
        .then(async paymentApiResponse => {
            console.log(`Resposta da API ${paymentMethod} (pedido ${newOrder._id}, Status HTTP Externo: ${paymentApiResponse.status}):`, JSON.stringify(paymentApiResponse.data, null, 2)); // Log formatado
            let paymentSuccessful = false;
            let transactionReference = null;
            let failureReason = 'Falha desconhecida.'; 

            if (paymentMethod.toLowerCase() === 'mpesa') {
                const mpesaData = paymentApiResponse.data;
                console.log("Processando resposta MPESA. Status HTTP da API Externa:", paymentApiResponse.status);

                switch (paymentApiResponse.status) { // Status HTTP da API Mpesa
                    case 200: 
                        console.log("MPESA: Entrou no case 200 HTTP.");
                        if (mpesaData && typeof mpesaData.status === 'string' && mpesaData.status.toLowerCase() === 'success') {
                            console.log("MPESA: Corpo da resposta tem 'status: success'.");
                            if (mpesaData.resposta && typeof mpesaData.resposta.status === 'number' && mpesaData.resposta.status === 200) {
                                console.log("MPESA: Estrutura aninhada 'resposta.status' é 200. SUCESSO COMPLETO.");
                                paymentSuccessful = true;
                                failureReason = ''; 
                                transactionReference = mpesaData.referenciaPagamento || mpesaData.transaction_id || `mpesa_success_${newOrder._id}`;
                            } else if (mpesaData.resposta && typeof mpesaData.resposta.status === 'number' && mpesaData.resposta.status !== 200) {
                                console.log(`MPESA: Corpo status 'success', mas resposta.status aninhada é ${mpesaData.resposta.status}. Considerando FALHA.`);
                                paymentSuccessful = false;
                                failureReason = `Mpesa HTTP 200 e corpo status 'success', mas resposta interna status ${mpesaData.resposta.status}. Detalhes: ${JSON.stringify(mpesaData.resposta).substring(0,100)}`;
                            } else if (!mpesaData.resposta) {
                                console.log("MPESA: Corpo status 'success', sem objeto 'resposta' aninhado. Considerando SUCESSO (flexível).");
                                paymentSuccessful = true;
                                failureReason = '';
                                transactionReference = mpesaData.referenciaPagamento || mpesaData.transaction_id || `mpesa_success_no_nested_response_${newOrder._id}`;
                            } else {
                                console.log("MPESA: Corpo status 'success', mas estrutura 'resposta' aninhada é inesperada. Considerando FALHA por precaução.");
                                paymentSuccessful = false;
                                failureReason = `Mpesa HTTP 200 e corpo status 'success', mas estrutura 'resposta' aninhada inválida: ${JSON.stringify(mpesaData.resposta).substring(0,100)}`;
                            }
                        } else {
                            console.log(`MPESA: HTTP 200, mas corpo não tem 'status: success' (valor: ${mpesaData ? mpesaData.status : 'null'}). FALHA.`);
                            paymentSuccessful = false;
                            failureReason = `Mpesa HTTP 200 mas corpo indica falha: ${JSON.stringify(mpesaData || {}).substring(0,100)}`;
                        }
                        break;
                    case 201: failureReason = mpesaData?.message || mpesaData?.error || JSON.stringify(mpesaData) || "Erro na Transação (Mpesa)"; break;
                    case 422: failureReason = mpesaData?.message || mpesaData?.error || JSON.stringify(mpesaData) || "Saldo Insuficiente (Mpesa)"; break;
                    case 400: failureReason = mpesaData?.message || mpesaData?.error || JSON.stringify(mpesaData) || "PIN Errado (Mpesa)"; break;
                    default: failureReason = `Erro API Mpesa (Status: ${paymentApiResponse.status}). Resposta: ${JSON.stringify(mpesaData || {}).substring(0,100)}`; break;
                }
                if (!paymentSuccessful) { 
                    newOrder.paymentStatus = 'failed'; 
                    newOrder.transactionId = failureReason; 
                }

            } else { // eMola
                if (paymentApiResponse.data && paymentApiResponse.data.success === 'yes') {
                    paymentSuccessful = true; 
                    transactionReference = paymentApiResponse.data.transaction_id || `emola_success_${newOrder._id}`;
                } else {
                    newOrder.paymentStatus = 'failed'; 
                    newOrder.transactionId = paymentApiResponse.data.message || 'Pagamento eMola reprovado';
                }
            }

            if (paymentSuccessful) {
                newOrder.paymentStatus = 'paid'; 
                newOrder.transactionId = transactionReference; 
                newOrder.subscriptionDetails.status = 'pending_admin_input';
                await newOrder.save();
                return res.status(200).json({ 
                    success: true, 
                    message: 'Pagamento realizado com sucesso! Seus dados da assinatura aparecerão em seu perfil em no máximo 10 minutos. Aguarde.', 
                    orderId: newOrder._id, 
                    paymentStatus: newOrder.paymentStatus, 
                    subscriptionStatus: newOrder.subscriptionDetails.status 
                });
            } else {
                await newOrder.save(); 
                return res.status(402).json({ 
                    success: false, 
                    message: `Pagamento falhou. Detalhes: ${newOrder.transactionId}`, 
                    orderId: newOrder._id, 
                    paymentStatus: newOrder.paymentStatus 
                });
            }
        })
        .catch(async error => { 
            console.error(`ERRO AXIOS ao chamar API de ${paymentMethod} para pedido ${newOrder._id}:`, error.message);
            let errorMsgDetail = `Erro de comunicação com API de pagamento: ${error.message.substring(0, 100)}`;
            if(error.response) { 
                console.error("Dados do erro da API:", error.response.data);
                console.error("Status do erro da API:", error.response.status);
                let apiErrorMsg = "Detalhes indisponíveis";
                if (typeof error.response.data === 'string') {
                    apiErrorMsg = error.response.data.substring(0,100);
                } else if (error.response.data && (error.response.data.message || error.response.data.error)) {
                    apiErrorMsg = JSON.stringify(error.response.data.message || error.response.data.error).substring(0,100);
                } else if (error.response.data) {
                    apiErrorMsg = JSON.stringify(error.response.data).substring(0,100);
                }
                errorMsgDetail = `Erro Servidor Pagamento (${error.response.status}): ${apiErrorMsg}`;
            } else if (error.request) { 
                console.error("Nenhuma resposta da API:", error.request);
                errorMsgDetail = "Sem resposta da API de pagamento.";
            }
            newOrder.paymentStatus = 'failed'; 
            newOrder.transactionId = errorMsgDetail;
            await newOrder.save();
            return res.status(500).json({ 
                success: false, 
                message: 'Ocorreu um erro crítico ao processar seu pagamento. Por favor, tente novamente mais tarde ou contacte o suporte.', 
                orderId: newOrder._id, 
                paymentStatus: newOrder.paymentStatus, 
                errorDetails: process.env.NODE_ENV === 'development' ? error.message : undefined 
            });
        });

    } catch (error) {
        console.error("Erro ao iniciar pagamento (geral):", error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'ID de produto inválido.' });
        }
        res.status(500).json({ message: 'Erro interno do servidor ao processar o pagamento.' });
    }
});
app.use('/api/payment', paymentRouter);
console.log("Rotas de pagamento definidas.");

// ============================
// MANIPULADOR DE ROTA NÃO ENCONTRADA (404)
// ============================
app.use((req, res, next) => {
    res.status(404).json({ message: `Rota não encontrada - ${req.originalUrl}` });
});

// ============================
// MANIPULADOR DE ERROS GLOBAL
// ============================
app.use((err, req, res, next) => {
    console.error("ERRO NÃO TRATADO:", err.stack); 
    const errorMessage = process.env.NODE_ENV === 'development' ? err.message : 'Ocorreu um erro inesperado no servidor.';
    const errorDetails = process.env.NODE_ENV === 'development' ? { name: err.name, message: err.message, stack: err.stack.substring(0, 500) } : {};
    res.status(err.status || 500).json({ 
        message: errorMessage,
        error: errorDetails 
    });
});

// ============================
// INICIALIZAÇÃO DO SERVIDOR
// ============================
app.listen(PORT, () => {
    console.log(`Servidor Stream Assinaturas rodando na porta ${PORT}`);
    console.log(`Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log('-----------------------------------------------------');
    console.log('Endpoints disponíveis (exemplos):');
    console.log(`  POST /api/auth/register     (Cadastro de usuário)`);
    console.log(`  POST /api/auth/login        (Login de usuário)`);
    console.log(`  GET  /api/products          (Listar produtos)`);
    console.log(`  GET  /api/products?activeOnly=true (Listar produtos ativos)`);
    console.log(`  POST /api/payment/initiate  (Iniciar pagamento)`);
    console.log(`  GET  /api/user/profile      (Perfil do usuário logado)`);
    console.log(`  GET  /api/user/subscriptions (Histórico de assinaturas do usuário)`);
    console.log(`  GET  /api/theme             (Obter tema atual)`);
    console.log('--- Admin Endpoints (requerem token de admin) ---');
    console.log(`  POST /api/products             (Criar produto - admin)`); // Rota de admin para produtos
    console.log(`  PUT  /api/products/:id        (Atualizar produto - admin)`);// Rota de admin para produtos
    console.log(`  GET  /api/admin/orders       (Listar todos os pedidos)`);
    console.log(`  PUT  /api/admin/orders/:orderId/credentials (Inserir credenciais)`);
    console.log(`  POST /api/admin/banners      (Criar banner)`);
    console.log('-----------------------------------------------------');
});

// Fim do arquivo server.js