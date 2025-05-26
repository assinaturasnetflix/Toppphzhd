const express = require('express');
const bodyParser = require('body-parser');
const https = require('https'); // Node.js built-in module for HTTPS requests

const app = express();
const port = 3000;

app.use(bodyParser.json());

// --- Secure Backend Configuration ---
// ⚠️ BEST PRACTICE: Use environment variables for sensitive data
const MOZPAYMENT_CARTEIRA_ID = process.env.MOZPAYMENT_CARTEIRA_ID || '1746519798335x143095610732969980'; // Your actual Wallet ID
const VALOR_PLANO_PREMIUM = process.env.VALOR_PLANO || '1.00'; // Price of the plan
const MOZPAYMENT_API_HOST = 'mozpayment.co.mz'; // Hostname from the URL
const MOZPAYMENT_API_PATH = '/api/1.1/wf/pagamentorotativoemola'; // Path from the URL
const WHATSAPP_NUMBER_FOR_LINK = process.env.WHATSAPP_NUMBER || '865097696';

if (MOZPAYMENT_CARTEIRA_ID === '1746519798335x143095610732969980') {
    console.warn("⚠️ WARNING: Using the example MozPayment Wallet ID. Ensure this is your correct ID and consider environment variables for production.");
}

// Serve the frontend (optional, for development)
app.get('/', (req, res) => {
    // Make sure 'index.html' is in the same directory or provide the correct path
    res.sendFile(__dirname + '/index.html');
});

app.post('/api/processar-pagamento-plano-premium', async (req, res) => {
    const { numero, quem_comprou } = req.body;

    if (!numero || !quem_comprou) {
        return res.status(400).json({
            payment_success: 'no',
            message: 'Número de telefone e nome são obrigatórios.'
        });
    }

    const paymentPayload = JSON.stringify({
        carteira: MOZPAYMENT_CARTEIRA_ID,
        numero: numero,
        'quem comprou': quem_comprou, // Key as specified
        valor: VALOR_PLANO_PREMIUM
    });

    console.log('Enviando para MozPayment:', paymentPayload);

    const options = {
        hostname: MOZPAYMENT_API_HOST,
        path: MOZPAYMENT_API_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(paymentPayload) // Important for POST requests
            // Add any other headers required by MozPayment API (e.g., API Key, Authorization)
        }
    };

    // --- Making the REAL API Call ---
    const apiRequest = https.request(options, (apiResponse) => {
        let responseBody = '';
        console.log(`MozPayment API Status Code: ${apiResponse.statusCode}`);
        apiResponse.setEncoding('utf8');

        apiResponse.on('data', (chunk) => {
            responseBody += chunk;
        });

        apiResponse.on('end', () => {
            console.log('Raw MozPayment API Response:', responseBody);
            try {
                const mozPaymentResponse = JSON.parse(responseBody);

                if (mozPaymentResponse.success === 'yes') {
                    const whatsappLink = `https://wa.me/258${WHATSAPP_NUMBER_FOR_LINK}?text=${encodeURIComponent(`Olá, meu pagamento para o Plano Premium (${VALOR_PLANO_PREMIUM} MZN) foi aprovado! Comprador: ${quem_comprou}, Número: ${numero}`)}`;
                    res.status(200).json({
                        payment_success: 'yes',
                        message: 'Pagamento aprovado pela MozPayment!',
                        whatsapp_link: whatsappLink,
                        api_response: mozPaymentResponse // Optionally send back API response details
                    });
                } else {
                    // Handle cases where 'success' is 'no' or not present
                    res.status(402).json({ // 402 Payment Required
                        payment_success: 'no',
                        message: `Pagamento reprovado pela MozPayment. ${mozPaymentResponse.message || mozPaymentResponse.reason || 'Motivo não especificado.'}`,
                        api_response: mozPaymentResponse
                    });
                }
            } catch (parseError) {
                console.error('Erro ao fazer parse da resposta JSON da MozPayment:', parseError);
                console.error('Corpo da resposta que causou o erro:', responseBody);
                res.status(500).json({
                    payment_success: 'no',
                    message: 'Erro ao processar a resposta do gateway de pagamento. Resposta inválida.',
                    raw_response: responseBody // Send raw response for debugging if it's not sensitive
                });
            }
        });
    });

    apiRequest.on('error', (error) => {
        console.error('Erro na requisição para MozPayment API:', error);
        res.status(500).json({
            payment_success: 'no',
            message: `Erro de comunicação com o gateway de pagamento: ${error.message}`
        });
    });

    // Send the payload
    apiRequest.write(paymentPayload);
    apiRequest.end(); // Finalize the request
});

app.listen(port, () => {
    console.log(`Servidor backend a rodar em http://localhost:${port}`);
    console.log("--- Configurações Atuais ---");
    console.log(`ID da Carteira MozPayment: ${MOZPAYMENT_CARTEIRA_ID.substring(0,5)}... (Verifique se é o correto!)`);
    console.log(`Valor do Plano: ${VALOR_PLANO_PREMIUM} MZN`);
    console.log(`Número WhatsApp para Link: ${WHATSAPP_NUMBER_FOR_LINK}`);
    console.log("--------------------------");
    if (!process.env.MOZPAYMENT_CARTEIRA_ID || !process.env.VALOR_PLANO || !process.env.WHATSAPP_NUMBER) {
        console.warn("⚠️ Para produção, defina MOZPAYMENT_CARTEIRA_ID, VALOR_PLANO, e WHATSAPP_NUMBER como variáveis de ambiente.");
    }
});
