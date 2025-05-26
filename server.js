const express = require('express');
const bodyParser = require('body-parser');
const https = require('https'); // Ou use 'axios'

const app = express();
const port = 3000;

app.use(bodyParser.json());

// --- Configurações Seguras do Backend ---
// ESTES VALORES NUNCA DEVEM IR PARA O FRONTEND
// Idealmente, viriam de variáveis de ambiente (process.env.MOZPAYMENT_CARTEIRA_ID)
const MOZPAYMENT_CARTEIRA_ID = '1746519798335x143095610732969980'; // SEU ID DE CARTEIRA REAL
const VALOR_PLANO_PREMIUM = '1.00'; // VALOR DO PLANO ESPECÍFICO
const MOZPAYMENT_API_URL = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativoemola';
const WHATSAPP_NUMBER_FOR_LINK = '865097696';

// Servir o frontend (opcional, para desenvolvimento)
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html'); // Assume que index.html está no mesmo diretório
});

// Endpoint específico para o Plano Premium
app.post('/api/processar-pagamento-plano-premium', async (req, res) => {
    const { numero, quem_comprou } = req.body; // Recebe apenas dados não sensíveis

    if (!numero || !quem_comprou) {
        return res.status(400).json({ payment_success: 'no', message: 'Número de telefone e nome são obrigatórios.' });
    }

    // Dados para a API MozPayment, agora com 'carteira' e 'valor' vindos do backend
    const paymentData = JSON.stringify({
        carteira: MOZPAYMENT_CARTEIRA_ID,       // Do backend
        numero: numero,                         // Do frontend
        'quem comprou': quem_comprou,           // Do frontend (atenção ao espaço no nome da chave)
        valor: VALOR_PLANO_PREMIUM              // Do backend
    });

    console.log('Preparando para enviar para MozPayment:', paymentData);

    // --- Lógica de Chamada à API MozPayment (SIMULAÇÃO OU REAL) ---
    // Substitua a simulação pela chamada real à API
    try {
        // SIMULAÇÃO (REMOVA/SUBSTITUA ESTE BLOCO EM PRODUÇÃO)
        const simulateMozPaymentCall = () => new Promise(resolve => {
            setTimeout(() => {
                const isSuccess = Math.random() > 0.2; // 80% de chance de sucesso para teste
                if (isSuccess) {
                    console.log('Simulação MozPayment: Aprovado');
                    resolve({ success: 'yes' });
                } else {
                    console.log('Simulação MozPayment: Reprovado');
                    resolve({ success: 'no', reason: 'Falha simulada' });
                }
            }, 1500);
        });
        const paymentApiResponse = await simulateMozPaymentCall(); // Use a chamada real aqui

        /*
        // EXEMPLO DE CHAMADA REAL COM 'https' (simplificado)
        // Use 'axios' ou similar para uma melhor experiência em produção
        const options = {
            hostname: 'mozpayment.co.mz', // Verifique o domínio correto
            path: '/api/1.1/wf/pagamentorotativoemola',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': paymentData.length,
                // Outros headers que a MozPayment possa exigir (ex: API Key)
            }
        };

        const paymentApiResponse = await new Promise((resolve, reject) => {
            const apiReq = https.request(options, apiRes => {
                let responseBody = '';
                apiRes.on('data', chunk => responseBody += chunk);
                apiRes.on('end', () => {
                    try {
                        resolve(JSON.parse(responseBody));
                    } catch (e) {
                        reject(new Error('Falha ao parsear resposta da MozPayment: ' + responseBody));
                    }
                });
            });
            apiReq.on('error', error => reject(error));
            apiReq.write(paymentData);
            apiReq.end();
        });
        */

        console.log('Resposta da MozPayment (simulada ou real):', paymentApiResponse);

        if (paymentApiResponse.success === 'yes') {
            const whatsappLink = `https://wa.me/258${WHATSAPP_NUMBER_FOR_LINK}?text=${encodeURIComponent(`Olá, meu pagamento para o Plano Premium foi aprovado! Comprador: ${quem_comprou}, Número: ${numero}`)}`;
            res.json({
                payment_success: 'yes',
                message: 'Pagamento aprovado!',
                whatsapp_link: whatsappLink
            });
        } else {
            res.status(402).json({ // 402 Payment Required pode ser mais semântico para falha de pagamento
                payment_success: 'no',
                message: `Pagamento reprovado. ${paymentApiResponse.reason || 'Motivo não especificado.'}`
            });
        }

    } catch (error) {
        console.error('Erro crítico ao processar pagamento:', error.message);
        res.status(500).json({
            payment_success: 'no',
            message: 'Erro interno do servidor ao tentar processar o pagamento.'
        });
    }
});

app.listen(port, () => {
    console.log(`Servidor backend a rodar em http://localhost:${port}`);
    console.log(`Frontend (se servido): http://localhost:${port}/`);
    console.log(`--- ATENÇÃO: MOZPAYMENT_CARTEIRA_ID e VALOR_PLANO_PREMIUM estão hardcoded. Em produção, use variáveis de ambiente! ---`);
});
