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

// Placeholder para rotas e lógica que virão depois
// ... models ...
// ... middlewares de autenticação ...
// ... rotas ...

// Definição da porta do servidor
const PORT = process.env.PORT || 3000;

// A inicialização do servidor (app.listen) será adicionada no final do arquivo.
// Por enquanto, esta é a configuração base.

// Placeholder para a função de criar admin padrão
async function createDefaultAdmin() {
    // Esta função será implementada na próxima parte, junto com o modelo User
    console.log("Verificando/criando admin padrão...");
}

console.log("Configuração inicial do server.js carregada.");
// server.js (continuação)

// ... (código anterior: importações, conexão com DB, etc.) ...

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
    // O histórico de assinaturas será gerenciado através do modelo Order
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
        unique: true, // Garante que não haja produtos com o mesmo nome
    },
    description: {
        type: String,
        required: [true, "A descrição do produto é obrigatória."],
    },
    image: { // Pode ser uma URL ou o caminho de um arquivo local (gerenciado pelo front/admin)
        type: String,
        required: [true, "A imagem do produto é obrigatória."],
    },
    price: {
        type: Number,
        required: [true, "O preço do produto é obrigatório."],
        min: [0, "O preço não pode ser negativo."],
    },
    // tipo: 'assinatura' ou 'giftcard' - podemos adicionar se necessário para diferenciar
    category: { // Ex: "Streaming de Vídeo", "Música", "Games", "Gift Cards"
        type: String,
        required: [true, "A categoria do produto é obrigatória."],
    },
    estimatedDeliveryTime: { // Em minutos
        type: String,
        default: "Máximo 10 minutos",
    },
    isActive: { // Para controlar se o produto está ativo para venda
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
    productName: String, // Para facilitar a exibição no histórico sem popular sempre
    productImage: String, // Para facilitar a exibição
    quantity: {
        type: Number,
        default: 1,
    },
    totalAmount: {
        type: Number,
        required: true,
    },
    paymentMethod: { // 'mpesa' ou 'emola'
        type: String,
        enum: ['mpesa', 'emola', 'pending'],
        default: 'pending',
    },
    paymentStatus: { // 'pending', 'paid', 'failed', 'processing_credentials'
        type: String,
        default: 'pending',
    },
    transactionId: { // ID da transação da API de pagamento
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
        } // 'pending_admin_input', 'delivered'
    },
    buyerInfo: { // Informações fornecidas no momento do pagamento
        phoneNumber: String,
        name: String,
    }
});

const Order = mongoose.model('Order', orderSchema);


// -------- ESQUEMA E MODELO DE BANNER (Banner) --------
const bannerSchema = new mongoose.Schema({
    title: { // Título opcional para o banner (uso interno ou display)
        type: String,
        trim: true,
    },
    imageUrl: { // URL da imagem ou caminho do arquivo (se hospedado localmente)
        type: String,
        required: [true, "A URL da imagem do banner é obrigatória."],
    },
    linkUrl: { // URL de destino ao clicar no banner (opcional)
        type: String,
        trim: true,
    },
    type: { // 'main' para banners principais, 'promotion' para banners de promoção
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
    description: { // Descrição opcional
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
    bannerOrVideoUrl: { // URL da imagem/vídeo ou caminho do arquivo
        type: String,
        required: [true, "O banner ou vídeo da promoção é obrigatório."],
    },
    isVide: {
        type: Boolean,
        default: false, // true se for um vídeo, false se for uma imagem/banner
    },
    linkUrl: { // Link opcional para a promoção
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
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            const adminPhoneNumber = process.env.ADMIN_DEFAULT_PHONE;
            const adminPassword = process.env.ADMIN_DEFAULT_PASSWORD;

            if (!adminPhoneNumber || !adminPassword) {
                console.warn("Variáveis de ambiente ADMIN_DEFAULT_PHONE ou ADMIN_DEFAULT_PASSWORD não definidas. Admin padrão não será criado.");
                return;
            }

            // Validação básica do número de telefone do admin
            if (!validator.isMobilePhone(adminPhoneNumber, 'any', { strictMode: false })) {
                console.warn(`Número de telefone do admin padrão ('${adminPhoneNumber}') inválido. Admin padrão não será criado.`);
                return;
            }

            const defaultAdmin = new User({
                phoneNumber: adminPhoneNumber,
                password: adminPassword, // O hook pre-save irá hashear
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

// ... (resto do código: middlewares de autenticação, rotas, etc.) ...
// server.js (continuação)

// ... (código anterior: models, createDefaultAdmin, etc.) ...

// ============================
// MIDDLEWARES DE AUTENTICAÇÃO
// ============================

// Middleware para verificar se o usuário está autenticado
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'Token não fornecido. Acesso não autorizado.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password'); // Não retorna a senha
        if (!user) {
            return res.status(403).json({ message: 'Usuário não encontrado. Token inválido.' });
        }
        req.user = user; // Adiciona o objeto do usuário à requisição
        next(); // Passa para o próximo middleware ou rota
    } catch (err) {
        console.error("Erro na verificação do token:", err.message);
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expirado. Por favor, faça login novamente.' });
        }
        return res.status(403).json({ message: 'Token inválido ou malformado.' });
    }
};

// Middleware para verificar se o usuário é um administrador
const isAdmin = (req, res, next) => {
    // Este middleware deve ser usado DEPOIS do authenticateToken
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        return res.status(403).json({ message: 'Acesso negado. Requer privilégios de administrador.' });
    }
};

console.log("Middlewares de autenticação definidos.");

// ... (resto do código: rotas, inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: middlewares de autenticação, etc.) ...

// ============================
// ROTAS DA API
// ============================

// -------- ROTAS DE AUTENTICAÇÃO (Públicas) --------
const authRouter = express.Router();

// Rota de Cadastro de Usuário (POST /api/auth/register)
authRouter.post('/register', async (req, res) => {
    const { phoneNumber, password } = req.body;

    if (!phoneNumber || !password) {
        return res.status(400).json({ message: 'Número de telefone e senha são obrigatórios.' });
    }

    // Validação do número de telefone
    if (!validator.isMobilePhone(phoneNumber.toString(), 'any', { strictMode: false })) {
        return res.status(400).json({ message: 'Formato de número de telefone inválido.' });
    }

    // Validação da senha
    if (password.length < 6) {
        return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    }

    try {
        const existingUser = await User.findOne({ phoneNumber });
        if (existingUser) {
            return res.status(409).json({ message: 'Este número de telefone já está cadastrado.' });
        }

        const newUser = new User({
            phoneNumber,
            password, // A senha será hasheada pelo hook pre-save do schema User
        });

        await newUser.save();

        // Gerar token JWT para o novo usuário após o cadastro bem-sucedido
        const token = jwt.sign(
            { userId: newUser._id, isAdmin: newUser.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' } // Token expira em 7 dias
        );

        res.status(201).json({
            message: 'Usuário cadastrado com sucesso!',
            token,
            user: {
                id: newUser._id,
                phoneNumber: newUser.phoneNumber,
                isAdmin: newUser.isAdmin
            }
        });

    } catch (error) {
        if (error.name === 'ValidationError') {
            // Captura erros de validação do Mongoose
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        console.error("Erro no cadastro:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar cadastrar usuário.' });
    }
});

// Rota de Login de Usuário (POST /api/auth/login)
authRouter.post('/login', async (req, res) => {
    const { phoneNumber, password } = req.body;

    if (!phoneNumber || !password) {
        return res.status(400).json({ message: 'Número de telefone e senha são obrigatórios.' });
    }

    try {
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas. Verifique o número de telefone.' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas. Verifique a senha.' });
        }

        // Gerar token JWT
        const token = jwt.sign(
            { userId: user._id, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' } // Token expira em 7 dias, pode ser ajustado
        );

        res.status(200).json({
            message: 'Login bem-sucedido!',
            token,
            user: {
                id: user._id,
                phoneNumber: user.phoneNumber,
                isAdmin: user.isAdmin
            }
        });

    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao tentar fazer login.' });
    }
});

// Usar o roteador de autenticação com o prefixo /api/auth
app.use('/api/auth', authRouter);

console.log("Rotas de autenticação (cadastro e login) definidas.");

// ... (resto do código: outras rotas, inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: rotas de autenticação, etc.) ...

// -------- ROTAS DE PRODUTOS (Protegidas - Admin) --------
const productRouter = express.Router();

// POST /api/products - Criar um novo produto (Admin)
productRouter.post('/', authenticateToken, isAdmin, async (req, res) => {
    const { name, description, image, price, category, estimatedDeliveryTime } = req.body;

    if (!name || !description || !image || price === undefined || !category) {
        return res.status(400).json({ message: 'Todos os campos obrigatórios (nome, descrição, imagem, preço, categoria) devem ser fornecidos.' });
    }
    if (typeof price !== 'number' || price < 0) {
        return res.status(400).json({ message: 'O preço deve ser um número não negativo.' });
    }

    try {
        const existingProduct = await Product.findOne({ name });
        if (existingProduct) {
            return res.status(409).json({ message: `Um produto com o nome '${name}' já existe.` });
        }

        const newProduct = new Product({
            name,
            description,
            image,
            price,
            category,
            estimatedDeliveryTime: estimatedDeliveryTime || "Máximo 10 minutos", // Valor padrão se não fornecido
        });

        const savedProduct = await newProduct.save();
        res.status(201).json({ message: 'Produto criado com sucesso!', product: savedProduct });
    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        console.error("Erro ao criar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar produto.' });
    }
});

// GET /api/products - Listar todos os produtos (Público, mas o admin pode ver todos, inclusive inativos)
// GET /api/products?activeOnly=true - Listar apenas produtos ativos (para usuários)
productRouter.get('/', async (req, res) => {
    try {
        const { activeOnly } = req.query;
        let query = {};

        // Se o parâmetro activeOnly=true for passado, filtra apenas produtos ativos
        // Caso contrário, ou se quem requisita é admin (verificação pode ser adicionada aqui se necessário),
        // retorna todos. Para simplificar, vamos focar no filtro por enquanto.
        if (activeOnly === 'true') {
            query.isActive = true;
        }
        // Se for um admin acessando, poderia ter uma lógica para não aplicar o filtro `isActive`
        // ou permitir um parâmetro tipo `showAll=true` que só admins poderiam usar.
        // Para o CRUD de admin, o admin geralmente vê tudo. Para a loja, o usuário vê apenas ativos.

        const products = await Product.find(query).sort({ createdAt: -1 }); // Ordena pelos mais recentes
        res.status(200).json(products);
    } catch (error) {
        console.error("Erro ao listar produtos:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar produtos.' });
    }
});

// GET /api/products/:id - Obter um produto específico (Público)
productRouter.get('/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Produto não encontrado.' });
        }
        // Adicionar verificação se o produto está inativo e quem está requisitando não é admin.
        // if (!product.isActive && (!req.user || !req.user.isAdmin)) {
        //     return res.status(404).json({ message: 'Produto não encontrado ou indisponível.' });
        // }
        res.status(200).json(product);
    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'ID de produto inválido.' });
        }
        console.error("Erro ao obter produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao obter produto.' });
    }
});

// PUT /api/products/:id - Atualizar um produto (Admin)
productRouter.put('/:id', authenticateToken, isAdmin, async (req, res) => {
    const { name, description, image, price, category, estimatedDeliveryTime, isActive } = req.body;

    // Validação básica
    if (price !== undefined && (typeof price !== 'number' || price < 0)) {
        return res.status(400).json({ message: 'O preço deve ser um número não negativo.' });
    }
    if (isActive !== undefined && typeof isActive !== 'boolean') {
        return res.status(400).json({ message: 'O status de ativo (isActive) deve ser um booleano.' });
    }

    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Produto não encontrado para atualização.' });
        }

        // Verifica se o novo nome já existe em outro produto
        if (name && name !== product.name) {
            const existingProduct = await Product.findOne({ name });
            if (existingProduct) {
                return res.status(409).json({ message: `Já existe um produto com o nome '${name}'.` });
            }
        }

        // Atualiza os campos fornecidos
        if (name) product.name = name;
        if (description) product.description = description;
        if (image) product.image = image;
        if (price !== undefined) product.price = price;
        if (category) product.category = category;
        if (estimatedDeliveryTime) product.estimatedDeliveryTime = estimatedDeliveryTime;
        if (isActive !== undefined) product.isActive = isActive;

        const updatedProduct = await product.save();
        res.status(200).json({ message: 'Produto atualizado com sucesso!', product: updatedProduct });
    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'ID de produto inválido.' });
        }
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        console.error("Erro ao atualizar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar produto.' });
    }
});

// DELETE /api/products/:id - Deletar um produto (Admin)
productRouter.delete('/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Produto não encontrado para deletar.' });
        }
        res.status(200).json({ message: 'Produto deletado com sucesso!', productId: req.params.id });
    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'ID de produto inválido.' });
        }
        console.error("Erro ao deletar produto:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar produto.' });
    }
});

// Usar o roteador de produtos com o prefixo /api/products
app.use('/api/products', productRouter);

console.log("Rotas CRUD para Produtos definidas.");

// ... (resto do código: outras rotas, inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: rotas de produtos, etc.) ...

// -------- ROTAS DO PERFIL DO USUÁRIO (Protegidas - Usuário Logado) --------
const userRouter = express.Router();

// GET /api/user/profile - Obter dados do perfil do usuário logado
userRouter.get('/profile', authenticateToken, async (req, res) => {
    // req.user é populado pelo middleware authenticateToken
    // Retornamos os dados do usuário sem a senha (já foi selecionada para não vir)
    res.status(200).json({
        id: req.user._id,
        phoneNumber: req.user.phoneNumber,
        registrationDate: req.user.registrationDate,
        isAdmin: req.user.isAdmin // Incluído para consistência, mas o front pode já saber
    });
});

// PUT /api/user/profile - Atualizar dados do perfil do usuário logado (ex: senha)
userRouter.put('/profile', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // Por enquanto, vamos permitir apenas a atualização da senha.
    // Outros campos como 'phoneNumber' geralmente exigem verificação adicional (ex: SMS OTP).

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres.' });
    }

    try {
        const user = await User.findById(req.user._id); // Busca o usuário completo para ter acesso à senha hasheada
        if (!user) {
            // Isso não deveria acontecer se authenticateToken funcionou, mas é uma boa verificação
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        // Se currentPassword for fornecida, verificar a senha atual antes de mudar
        if (currentPassword) {
            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) {
                return res.status(401).json({ message: 'Senha atual incorreta.' });
            }
        } else {
            // Se não for admin e não fornecer senha atual, não permitir alteração
            // (Admin poderia alterar senhas sem saber a atual, mas isso não está implementado aqui)
            if (!req.user.isAdmin) {
                 return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha.' });
            }
        }


        user.password = newPassword; // O hook pre-save irá hashear a nova senha
        await user.save();

        res.status(200).json({ message: 'Senha atualizada com sucesso.' });

    } catch (error) {
        console.error("Erro ao atualizar perfil do usuário:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar perfil.' });
    }
});


// GET /api/user/subscriptions - Obter histórico de assinaturas (pedidos) do usuário logado
userRouter.get('/subscriptions', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user._id })
            .populate('product', 'name image category') // Popula com alguns dados do produto
            .sort({ orderDate: -1 }); // Ordena pelas mais recentes

        res.status(200).json(orders);
    } catch (error) {
        console.error("Erro ao buscar histórico de assinaturas:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar histórico de assinaturas.' });
    }
});

// GET /api/user/subscription/:orderId/credentials - Obter credenciais de uma assinatura específica
// Esta rota é crucial para o usuário ver os dados da conta (e-mail/senha da assinatura)
userRouter.get('/subscription/:orderId/credentials', authenticateToken, async (req, res) => {
    const { orderId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(orderId)) {
        return res.status(400).json({ message: 'ID do pedido inválido.' });
    }

    try {
        const order = await Order.findOne({ _id: orderId, user: req.user._id });

        if (!order) {
            return res.status(404).json({ message: 'Pedido não encontrado ou não pertence a este usuário.' });
        }

        // Verifica se os detalhes da assinatura já foram entregues pelo admin
        if (order.subscriptionDetails && order.subscriptionDetails.status === 'delivered') {
            res.status(200).json({
                orderId: order._id,
                productName: order.productName, // Pode ser pego do populate se preferir
                email: order.subscriptionDetails.email,
                password: order.subscriptionDetails.password, // Considere implicações de segurança de enviar a senha diretamente.
                                                             // Uma alternativa seria exibir apenas uma vez ou usar um "mostrar senha".
                                                             // Para o requisito de "ficar visível mesmo após recarregar", armazenar no estado do front é uma opção.
            });
        } else if (order.paymentStatus === 'paid' && order.subscriptionDetails.status === 'pending_admin_input') {
            res.status(202).json({ // 202 Accepted (indica que a solicitação foi aceita, mas o processamento não foi concluído)
                orderId: order._id,
                productName: order.productName,
                message: "Seus dados da assinatura aparecerão aqui em no máximo 10 minutos. Aguarde.",
                status: order.subscriptionDetails.status
            });
        } else if (order.paymentStatus !== 'paid') {
            res.status(402).json({ // 402 Payment Required (embora já pago, pode indicar que algo está pendente)
                orderId: order._id,
                productName: order.productName,
                message: "O pagamento deste pedido ainda não foi confirmado ou falhou.",
                status: order.paymentStatus
            });
        }
         else {
            res.status(204).json({ // 204 No Content ou um status específico
                 message: "Detalhes da assinatura ainda não disponíveis ou houve um erro.",
                 status: order.subscriptionDetails.status
            });
        }
    } catch (error) {
        console.error("Erro ao buscar credenciais da assinatura:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao buscar credenciais.' });
    }
});


// Usar o roteador do usuário com o prefixo /api/user
app.use('/api/user', userRouter);

console.log("Rotas do perfil do usuário definidas.");

// ... (resto do código: outras rotas, inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: rotas do perfil do usuário, etc.) ...

// ========================================
// ROTAS DO PAINEL ADMINISTRATIVO
// ========================================
const adminRouter = express.Router();

// Aplicar middlewares de autenticação e verificação de admin para todas as rotas do adminRouter
adminRouter.use(authenticateToken, isAdmin);

// -------- GERENCIAMENTO DE BANNERS (Admin) --------
// POST /api/admin/banners - Criar banner
adminRouter.post('/banners', async (req, res) => {
    const { title, imageUrl, linkUrl, type, isActive } = req.body;
    if (!imageUrl || !type) {
        return res.status(400).json({ message: 'URL da imagem e tipo do banner são obrigatórios.' });
    }
    try {
        const newBanner = new Banner({ title, imageUrl, linkUrl, type, isActive });
        await newBanner.save();
        res.status(201).json({ message: 'Banner criado com sucesso!', banner: newBanner });
    } catch (error) {
        console.error("Erro ao criar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar banner.' });
    }
});

// GET /api/admin/banners - Listar todos os banners
adminRouter.get('/banners', async (req, res) => {
    try {
        const banners = await Banner.find().sort({ createdAt: -1 });
        res.status(200).json(banners);
    } catch (error) {
        console.error("Erro ao listar banners:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar banners.' });
    }
});

// PUT /api/admin/banners/:id - Atualizar banner
adminRouter.put('/banners/:id', async (req, res) => {
    try {
        const updatedBanner = await Banner.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedBanner) return res.status(404).json({ message: 'Banner não encontrado.' });
        res.status(200).json({ message: 'Banner atualizado com sucesso!', banner: updatedBanner });
    } catch (error) {
        console.error("Erro ao atualizar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar banner.' });
    }
});

// DELETE /api/admin/banners/:id - Deletar banner
adminRouter.delete('/banners/:id', async (req, res) => {
    try {
        const deletedBanner = await Banner.findByIdAndDelete(req.params.id);
        if (!deletedBanner) return res.status(404).json({ message: 'Banner não encontrado.' });
        res.status(200).json({ message: 'Banner deletado com sucesso!', bannerId: req.params.id });
    } catch (error) {
        console.error("Erro ao deletar banner:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar banner.' });
    }
});


// -------- GERENCIAMENTO DE COUNTDOWNS (Admin) --------
// POST /api/admin/countdowns - Criar countdown
adminRouter.post('/countdowns', async (req, res) => {
    const { title, endDate, description, isActive } = req.body;
    if (!title || !endDate) {
        return res.status(400).json({ message: 'Título e data final são obrigatórios para o countdown.' });
    }
    try {
        const newCountdown = new Countdown({ title, endDate, description, isActive });
        await newCountdown.save();
        res.status(201).json({ message: 'Countdown criado com sucesso!', countdown: newCountdown });
    } catch (error) {
        console.error("Erro ao criar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar countdown.' });
    }
});

// GET /api/admin/countdowns - Listar todos os countdowns
adminRouter.get('/countdowns', async (req, res) => {
    try {
        const countdowns = await Countdown.find().sort({ createdAt: -1 });
        res.status(200).json(countdowns);
    } catch (error) {
        console.error("Erro ao listar countdowns:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar countdowns.' });
    }
});

// PUT /api/admin/countdowns/:id - Atualizar countdown
adminRouter.put('/countdowns/:id', async (req, res) => {
    try {
        const updatedCountdown = await Countdown.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedCountdown) return res.status(404).json({ message: 'Countdown não encontrado.' });
        res.status(200).json({ message: 'Countdown atualizado com sucesso!', countdown: updatedCountdown });
    } catch (error) {
        console.error("Erro ao atualizar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar countdown.' });
    }
});

// DELETE /api/admin/countdowns/:id - Deletar countdown
adminRouter.delete('/countdowns/:id', async (req, res) => {
    try {
        const deletedCountdown = await Countdown.findByIdAndDelete(req.params.id);
        if (!deletedCountdown) return res.status(404).json({ message: 'Countdown não encontrado.' });
        res.status(200).json({ message: 'Countdown deletado com sucesso!', countdownId: req.params.id });
    } catch (error) {
        console.error("Erro ao deletar countdown:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar countdown.' });
    }
});


// -------- GERENCIAMENTO DE PROMOÇÕES (Admin) --------
// POST /api/admin/promotions - Criar promoção
adminRouter.post('/promotions', async (req, res) => {
    const { title, description, bannerOrVideoUrl, isVideo, linkUrl, isActive, startDate, endDate } = req.body;
    if (!title || !description || !bannerOrVideoUrl) {
        return res.status(400).json({ message: 'Título, descrição e URL do banner/vídeo são obrigatórios.' });
    }
    try {
        const newPromotion = new Promotion({ title, description, bannerOrVideoUrl, isVideo, linkUrl, isActive, startDate, endDate });
        await newPromotion.save();
        res.status(201).json({ message: 'Promoção criada com sucesso!', promotion: newPromotion });
    } catch (error) {
        console.error("Erro ao criar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao criar promoção.' });
    }
});

// GET /api/admin/promotions - Listar todas as promoções
adminRouter.get('/promotions', async (req, res) => {
    try {
        const promotions = await Promotion.find().sort({ createdAt: -1 });
        res.status(200).json(promotions);
    } catch (error) {
        console.error("Erro ao listar promoções:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar promoções.' });
    }
});

// PUT /api/admin/promotions/:id - Atualizar promoção
adminRouter.put('/promotions/:id', async (req, res) => {
    try {
        const updatedPromotion = await Promotion.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedPromotion) return res.status(404).json({ message: 'Promoção não encontrada.' });
        res.status(200).json({ message: 'Promoção atualizada com sucesso!', promotion: updatedPromotion });
    } catch (error) {
        console.error("Erro ao atualizar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar promoção.' });
    }
});

// DELETE /api/admin/promotions/:id - Deletar promoção
adminRouter.delete('/promotions/:id', async (req, res) => {
    try {
        const deletedPromotion = await Promotion.findByIdAndDelete(req.params.id);
        if (!deletedPromotion) return res.status(404).json({ message: 'Promoção não encontrada.' });
        res.status(200).json({ message: 'Promoção deletada com sucesso!', promotionId: req.params.id });
    } catch (error) {
        console.error("Erro ao deletar promoção:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao deletar promoção.' });
    }
});


// -------- GERENCIAMENTO DE USUÁRIOS (Admin) --------
// GET /api/admin/users - Listar todos os usuários
adminRouter.get('/users', async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ registrationDate: -1 }); // Exclui a senha
        res.status(200).json(users);
    } catch (error) {
        console.error("Erro ao listar usuários:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar usuários.' });
    }
});

// GET /api/admin/users/:userId - Ver detalhes de um usuário específico
adminRouter.get('/users/:userId', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        // Buscar também o histórico de compras deste usuário
        const orders = await Order.find({ user: req.params.userId })
                                  .populate('product', 'name price')
                                  .sort({ orderDate: -1 });
        res.status(200).json({ user, orders });
    } catch (error) {
        console.error("Erro ao buscar detalhes do usuário:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// PUT /api/admin/users/:userId - Atualizar um usuário (ex: tornar admin, desativar - não implementado)
// ... (Pode ser expandido conforme necessidade)


// -------- GERENCIAMENTO DE PEDIDOS E CREDENCIAIS (Admin) --------
// GET /api/admin/orders - Listar todos os pedidos
adminRouter.get('/orders', async (req, res) => {
    try {
        // Paginação simples
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20; // 20 pedidos por página
        const skip = (page - 1) * limit;

        let filter = {};
        // Filtrar por status do pagamento ou status da credencial, se fornecido
        if (req.query.paymentStatus) filter.paymentStatus = req.query.paymentStatus;
        if (req.query.credentialStatus) filter['subscriptionDetails.status'] = req.query.credentialStatus;


        const orders = await Order.find(filter)
            .populate('user', 'phoneNumber') // Adiciona número do usuário
            .populate('product', 'name') // Adiciona nome do produto
            .sort({ orderDate: -1 })
            .skip(skip)
            .limit(limit);

        const totalOrders = await Order.countDocuments(filter);

        res.status(200).json({
            orders,
            currentPage: page,
            totalPages: Math.ceil(totalOrders / limit),
            totalOrders
        });
    } catch (error) {
        console.error("Erro ao listar pedidos:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao listar pedidos.' });
    }
});

// GET /api/admin/orders/:orderId - Ver detalhes de um pedido específico
adminRouter.get('/orders/:orderId', async (req, res) => {
    try {
        const order = await Order.findById(req.params.orderId)
                                  .populate('user', 'phoneNumber registrationDate')
                                  .populate('product', 'name description image category');
        if (!order) {
            return res.status(404).json({ message: 'Pedido não encontrado.' });
        }
        res.status(200).json(order);
    } catch (error) {
        console.error("Erro ao buscar detalhes do pedido:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// PUT /api/admin/orders/:orderId/credentials - Inserir/Atualizar dados da conta (e-mail/senha) da assinatura
adminRouter.put('/orders/:orderId/credentials', async (req, res) => {
    const { orderId } = req.params;
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'E-mail e senha da assinatura são obrigatórios.' });
    }
    if (!mongoose.Types.ObjectId.isValid(orderId)) {
        return res.status(400).json({ message: 'ID do pedido inválido.' });
    }

    try {
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Pedido não encontrado.' });
        }

        // Só permite inserir credenciais se o pagamento estiver confirmado
        if (order.paymentStatus !== 'paid') {
            return res.status(400).json({ message: 'Não é possível adicionar credenciais a um pedido não pago ou pendente.' });
        }

        order.subscriptionDetails.email = email;
        order.subscriptionDetails.password = password; // A senha da assinatura é armazenada como fornecida
        order.subscriptionDetails.status = 'delivered';

        await order.save();
        // Aqui você pode adicionar lógica para notificar o usuário (ex: WebSocket, e-mail - fora do escopo atual)

        res.status(200).json({ message: 'Dados da assinatura atualizados com sucesso!', order });
    } catch (error) {
        console.error("Erro ao atualizar credenciais do pedido:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao atualizar credenciais.' });
    }
});


// Rota para alterar tema (placeholder, apenas salva a configuração)
// No frontend, você buscaria essa configuração para aplicar o tema.
// Poderia ser armazenado em um model 'SiteSettings' ou similar.
let currentTheme = { primaryColor: '#007bff', accentColor: '#6c757d', season: 'default' }; // Tema padrão

adminRouter.post('/theme', (req, res) => {
    const { primaryColor, accentColor, season } = req.body;
    if (primaryColor) currentTheme.primaryColor = primaryColor;
    if (accentColor) currentTheme.accentColor = accentColor;
    if (season) currentTheme.season = season;
    // Idealmente, isso seria salvo no banco de dados em uma coleção de configurações.
    console.log("Tema atualizado para:", currentTheme);
    res.status(200).json({ message: 'Tema atualizado (simulado).', theme: currentTheme });
});

// Rota para buscar o tema atual (para o front-end usar)
// Esta rota não precisa de autenticação de admin, pois o front do usuário precisará dela.
// Vamos criar uma rota pública para isso fora do adminRouter.


// Usar o roteador de admin com o prefixo /api/admin
app.use('/api/admin', adminRouter);

// Rota pública para buscar o tema atual
app.get('/api/theme', (req, res) => {
    // Em uma implementação real, você buscaria do DB.
    res.status(200).json(currentTheme);
});


console.log("Rotas do painel administrativo definidas.");

// ... (resto do código: rotas de pagamento, inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: rotas do admin, etc.) ...

// ============================
// ROTAS DE PAGAMENTO
// ============================
const paymentRouter = express.Router();

// Middleware de autenticação é necessário para saber quem está comprando
paymentRouter.use(authenticateToken);

// POST /api/payment/initiate - Iniciar um pagamento
paymentRouter.post('/initiate', async (req, res) => {
    const { productId, paymentMethod, buyerPhoneNumber, buyerName } = req.body;
    const userId = req.user._id; // ID do usuário logado

    if (!productId || !paymentMethod || !buyerPhoneNumber || !buyerName) {
        return res.status(400).json({ message: 'ID do produto, método de pagamento, número de telefone do pagador e nome do pagador são obrigatórios.' });
    }

    if (!['mpesa', 'emola'].includes(paymentMethod.toLowerCase())) {
        return res.status(400).json({ message: 'Método de pagamento inválido. Aceitos: mpesa, emola.' });
    }

    // Validação do número de telefone do pagador
    if (!validator.isMobilePhone(buyerPhoneNumber.toString(), 'any', { strictMode: false })) {
        return res.status(400).json({ message: 'Formato de número de telefone do pagador inválido.' });
    }

    try {
        const product = await Product.findById(productId);
        if (!product || !product.isActive) {
            return res.status(404).json({ message: 'Produto não encontrado ou indisponível.' });
        }

        const amount = product.price;

        // 1. Criar um pedido inicial no banco com status 'pending'
        const newOrder = new Order({
            user: userId,
            product: productId,
            productName: product.name, // Armazenar para referência rápida
            productImage: product.image, // Armazenar para referência rápida
            totalAmount: amount,
            paymentMethod: paymentMethod.toLowerCase(),
            paymentStatus: 'pending', // Status inicial
            buyerInfo: {
                phoneNumber: buyerPhoneNumber,
                name: buyerName,
            },
            subscriptionDetails: { // Inicializa com status pending_admin_input
                email: null,
                password: null,
                status: 'pending_admin_input'
            }
        });
        await newOrder.save();

        // 2. Preparar a chamada para a API de pagamento
        const paymentApiUrl = paymentMethod.toLowerCase() === 'mpesa' ? MPESA_API_URL : EMOLA_API_URL;
        const paymentPayload = {
            carteira: PAYMENT_WALLET_ID,
            numero: buyerPhoneNumber,
            "quem comprou": buyerName, // As chaves devem ser exatamente como na especificação
            valor: amount.toString(), // API espera valor como string
        };

        // Simulação de animação de carregamento no front-end (o backend não envia animação)
        // O front-end deve exibir um loader ao chamar esta API.
        // O backend agora fará a chamada para a API de pagamento.

        console.log(`Iniciando pagamento para pedido ${newOrder._id} via ${paymentMethod} com payload:`, paymentPayload);

        // 3. Chamar a API de pagamento externa
        axios.post(paymentApiUrl, paymentPayload, {
            headers: {
                // Adicionar quaisquer headers necessários, como 'Content-Type': 'application/json'
                // ou tokens de autenticação para a API de pagamento, se houver.
                // Pelas URLs fornecidas, parece ser um endpoint público ou com autenticação embutida.
                'Content-Type': 'application/json'
            }
        })
        .then(async paymentApiResponse => {
            // Processar a resposta da API de pagamento
            console.log(`Resposta da API de ${paymentMethod} para pedido ${newOrder._id}:`, paymentApiResponse.data);
            let paymentSuccessful = false;
            let transactionReference = null; // Ou algum ID da resposta

            if (paymentMethod.toLowerCase() === 'mpesa') {
                // Respostas MPESA: 200 = Sucesso, 201 = Erro, 422 = Saldo insuficiente, 400 = PIN errado
                if (paymentApiResponse.status === 200) { // Supondo que 200 OK seja sucesso no corpo também
                     // A API do mpesa da Printf é um pouco diferente, ela retorna 200 e no corpo tem o `status`
                    if (paymentApiResponse.data && paymentApiResponse.data.status === "Pagamento efectuado com sucesso") {
                        paymentSuccessful = true;
                        transactionReference = paymentApiResponse.data.referenciaPagamento || `mpesa_${newOrder._id}`;
                    } else {
                        // Mesmo com status HTTP 200, o pagamento pode ter falhado internamente
                        newOrder.paymentStatus = 'failed';
                        // Guardar a mensagem de erro da API se disponível
                        newOrder.transactionId = paymentApiResponse.data.mensagem || 'Falha no Mpesa';
                    }
                } else {
                    newOrder.paymentStatus = 'failed';
                    // Guardar a mensagem de erro da API se disponível
                    const errorMsg = paymentApiResponse.data ? (paymentApiResponse.data.message || paymentApiResponse.data.error || JSON.stringify(paymentApiResponse.data)) : `Erro ${paymentApiResponse.status}`;
                    newOrder.transactionId = errorMsg;
                }
            } else { // eMola
                // Respostas EMOLA: success = yes (pagamento aprovado), success = no (pagamento reprovado)
                if (paymentApiResponse.data && paymentApiResponse.data.success === 'yes') {
                    paymentSuccessful = true;
                    transactionReference = paymentApiResponse.data.transaction_id || `emola_${newOrder._id}`; // Supondo que haja um transaction_id
                } else {
                    newOrder.paymentStatus = 'failed';
                    newOrder.transactionId = paymentApiResponse.data.message || 'Pagamento eMola reprovado';
                }
            }

            if (paymentSuccessful) {
                newOrder.paymentStatus = 'paid';
                newOrder.transactionId = transactionReference;
                // Os dados da assinatura (e-mail/senha) ainda estão pendentes de input do admin
                newOrder.subscriptionDetails.status = 'pending_admin_input';
                await newOrder.save();

                // Resposta para o front-end indicando sucesso no pagamento e espera pelas credenciais
                // O frontend deve mostrar animação de sucesso e a mensagem de espera.
                return res.status(200).json({
                    success: true,
                    message: 'Pagamento realizado com sucesso! Seus dados da assinatura aparecerão em seu perfil em no máximo 10 minutos. Aguarde.',
                    orderId: newOrder._id,
                    paymentStatus: newOrder.paymentStatus,
                    subscriptionStatus: newOrder.subscriptionDetails.status
                });
            } else {
                // Pagamento falhou
                await newOrder.save(); // Salva o status 'failed' e a mensagem de erro no pedido
                return res.status(402).json({ // 402 Payment Required (ou outro código de erro apropriado)
                    success: false,
                    message: `Pagamento falhou. Detalhes: ${newOrder.transactionId}`,
                    orderId: newOrder._id,
                    paymentStatus: newOrder.paymentStatus
                });
            }
        })
        .catch(async error => {
            // Erro na chamada para a API de pagamento (ex: rede, API fora do ar)
            console.error(`Erro ao chamar API de ${paymentMethod} para pedido ${newOrder._id}:`, error.response ? error.response.data : error.message);
            newOrder.paymentStatus = 'failed';
            newOrder.transactionId = `Erro na comunicação com a API de pagamento: ${error.message}`;
            await newOrder.save();

            return res.status(500).json({
                success: false,
                message: 'Ocorreu um erro ao processar seu pagamento. Por favor, tente novamente mais tarde.',
                orderId: newOrder._id,
                paymentStatus: newOrder.paymentStatus,
                errorDetails: error.message
            });
        });

        // O front-end deve exibir o loader aqui. A resposta final virá do .then() ou .catch() da chamada axios.
        // Não enviar uma resposta aqui, pois a chamada axios é assíncrona.

    } catch (error) {
        console.error("Erro ao iniciar pagamento:", error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'ID de produto inválido.' });
        }
        res.status(500).json({ message: 'Erro interno do servidor ao processar o pagamento.' });
    }
});


// Usar o roteador de pagamento com o prefixo /api/payment
app.use('/api/payment', paymentRouter);

console.log("Rotas de pagamento definidas.");

// ... (inicialização do servidor, etc.) ...
// server.js (continuação)

// ... (código anterior: rotas de pagamento, etc.) ...

// ============================
// MANIPULADOR DE ROTA NÃO ENCONTRADA (404)
// ============================
// Este middleware deve ser o último, após todas as outras rotas e middlewares
app.use((req, res, next) => {
    res.status(404).json({ message: `Rota não encontrada - ${req.originalUrl}` });
});

// ============================
// MANIPULADOR DE ERROS GLOBAL (Opcional, mas bom para pegar erros não tratados)
// ============================
// Este middleware de tratamento de erros deve ter 4 argumentos
app.use((err, req, res, next) => {
    console.error("ERRO NÃO TRATADO:", err.stack); // Loga o stack trace do erro no console do servidor
    // Não envie o stack trace para o cliente em produção por razões de segurança
    res.status(500).json({
        message: 'Ocorreu um erro inesperado no servidor.',
        // error: process.env.NODE_ENV === 'development' ? err.message : {} // Apenas em desenvolvimento
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
    console.log('--- Admin Endpoints (requerem token de admin) ---');
    console.log(`  POST /api/admin/products     (Criar produto)`);
    console.log(`  GET  /api/admin/orders       (Listar todos os pedidos)`);
    console.log(`  PUT  /api/admin/orders/:orderId/credentials (Inserir credenciais)`);
    console.log('-----------------------------------------------------');
});

// Fim do arquivo server.js