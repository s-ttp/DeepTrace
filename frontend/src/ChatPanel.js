import React, { useState, useRef, useEffect } from 'react';

/**
 * ChatPanel - Trace-aware chatbot component
 * Provides two modes:
 * - Trace Q&A: Grounded in trace evidence
 * - Tech Explainer: Educational mode for telecom concepts
 */
function ChatPanel({ jobId, onClose }) {
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [mode, setMode] = useState('trace'); // 'trace' or 'explain'
    const [isLoading, setIsLoading] = useState(false);
    const messagesEndRef = useRef(null);

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Quick action buttons
    const quickActions = [
        { label: '📋 Summarize failures', message: 'Summarize the main failures and issues in this trace.' },
        { label: '🔍 Show evidence', message: 'What specific evidence supports the root cause findings?' },
        { label: '❓ Explain root cause', message: 'Explain the main root cause identified in this analysis.' },
        { label: '📡 What to capture next?', message: 'What additional capture points or data would help diagnose this issue further?' },
    ];

    const sendMessage = async (messageText) => {
        if (!messageText.trim() || isLoading) return;

        const userMessage = { role: 'user', content: messageText };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            const response = await fetch('/api/chat/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    job_id: jobId,
                    message: messageText,
                    mode: mode
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to get response');
            }

            const data = await response.json();

            const assistantMessage = {
                role: 'assistant',
                content: data.answer,
                citations: data.citations || []
            };

            setMessages(prev => [...prev, assistantMessage]);
        } catch (error) {
            console.error('Chat error:', error);
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `Error: ${error.message}`,
                isError: true
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        sendMessage(input);
    };

    const handleQuickAction = (message) => {
        setInput(message);
        sendMessage(message);
    };

    return (
        <div className="chat-panel">
            <div className="chat-header">
                <div className="chat-title">
                    <span className="chat-icon">🤖</span>
                    <span>DeepTrace Assistant</span>
                </div>
                <button className="chat-close-btn" onClick={onClose}>×</button>
            </div>

            <div className="chat-mode-toggle">
                <button
                    className={`mode-btn ${mode === 'trace' ? 'active' : ''}`}
                    onClick={() => setMode('trace')}
                >
                    🎯 Trace Q&A
                </button>
                <button
                    className={`mode-btn ${mode === 'explain' ? 'active' : ''}`}
                    onClick={() => setMode('explain')}
                >
                    📚 Tech Explainer
                </button>
            </div>

            <div className="chat-messages">
                {messages.length === 0 && (
                    <div className="chat-welcome">
                        <p>👋 Ask me about this trace!</p>
                        <p className="chat-hint">
                            {mode === 'trace'
                                ? 'I will only reference evidence from this capture.'
                                : 'I can explain telecom concepts and relate them to this trace.'}
                        </p>
                    </div>
                )}

                {messages.map((msg, idx) => (
                    <div key={idx} className={`chat-message ${msg.role} ${msg.isError ? 'error' : ''}`}>
                        <div className="message-content">
                            {msg.content}
                        </div>
                        {msg.citations && msg.citations.length > 0 && (
                            <div className="message-citations">
                                <span className="citations-label">📌 Evidence:</span>
                                {msg.citations.map((cite, i) => (
                                    <span key={i} className="citation-tag">{cite}</span>
                                ))}
                            </div>
                        )}
                    </div>
                ))}

                {isLoading && (
                    <div className="chat-message assistant loading">
                        <div className="loading-dots">
                            <span></span><span></span><span></span>
                        </div>
                    </div>
                )}

                <div ref={messagesEndRef} />
            </div>

            <div className="quick-actions">
                {quickActions.map((action, idx) => (
                    <button
                        key={idx}
                        className="quick-action-btn"
                        onClick={() => handleQuickAction(action.message)}
                        disabled={isLoading}
                    >
                        {action.label}
                    </button>
                ))}
            </div>

            <form className="chat-input-form" onSubmit={handleSubmit}>
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={mode === 'trace' ? 'Ask about this trace...' : 'Ask about telecom concepts...'}
                    disabled={isLoading}
                    className="chat-input"
                />
                <button
                    type="submit"
                    disabled={isLoading || !input.trim()}
                    className="chat-send-btn"
                >
                    ➤
                </button>
            </form>
        </div>
    );
}

export default ChatPanel;
