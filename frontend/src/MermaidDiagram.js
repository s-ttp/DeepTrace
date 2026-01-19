import React, { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

// Initialize mermaid (safe to call multiple times)
const initMermaid = () => {
    try {
        mermaid.initialize({
            startOnLoad: false,
            theme: 'dark',
            securityLevel: 'loose',
            themeVariables: {
                primaryColor: '#8b5cf6',
                primaryTextColor: '#f8fafc',
                primaryBorderColor: '#8b5cf6',
                lineColor: '#06b6d4',
                secondaryColor: '#1e293b',
                tertiaryColor: '#0f172a',
                background: '#020617',
                mainBkg: '#0f172a',
                secondBkg: '#1e293b',
                noteBkgColor: 'rgba(139, 92, 246, 0.2)',
                noteTextColor: '#f8fafc',
                noteBorderColor: '#8b5cf6',
                actorBkg: '#1e293b',
                actorBorder: '#8b5cf6',
                actorTextColor: '#f8fafc',
                actorLineColor: '#64748b',
                signalColor: '#f8fafc',
                signalTextColor: '#f8fafc',
                labelBoxBkgColor: '#1e293b',
                labelBoxBorderColor: '#8b5cf6',
                labelTextColor: '#f8fafc',
            },
            sequence: {
                diagramMarginX: 20,
                diagramMarginY: 20,
                actorMargin: 50,
                width: 150,
                height: 65,
                boxMargin: 10,
                boxTextMargin: 5,
                noteMargin: 10,
                messageMargin: 35,
                mirrorActors: false,
                bottomMarginAdj: 10,
                useMaxWidth: true,
                rightAngles: false,
                showSequenceNumbers: true,
            }
        });
    } catch (e) {
        console.warn("Mermaid initialization warning:", e);
    }
};

const MermaidDiagram = ({ chart }) => {
    const containerRef = useRef(null);
    const [svg, setSvg] = useState('');
    const [error, setError] = useState(null);

    useEffect(() => {
        initMermaid();
    }, []);

    useEffect(() => {
        if (!chart || !containerRef.current) return;

        const renderDiagram = async () => {
            try {
                setError(null);
                // Generate a unique ID for this render
                const id = `mermaid-${Math.random().toString(36).substr(2, 9)}`;

                // Ensure chart is valid string
                if (typeof chart !== 'string' || !chart.trim()) {
                    return;
                }

                // Render
                const { svg: renderedSvg } = await mermaid.render(id, chart);
                setSvg(renderedSvg);
            } catch (err) {
                console.error("Mermaid rendering failed:", err);
                setError("Failed to render diagram. Syntax might be invalid.");

                // Fallback: Show raw text if render fails
                setSvg('');
            }
        };

        renderDiagram();
    }, [chart]);

    if (error) {
        return (
            <div className="mermaid-error" style={{ color: '#ef4444', padding: '1rem', border: '1px solid #ef4444', borderRadius: '8px' }}>
                <p>⚠️ {error}</p>
                <pre style={{ fontSize: '0.8rem', marginTop: '0.5rem', overflowX: 'auto' }}>{chart}</pre>
            </div>
        );
    }

    return (
        <div
            className="mermaid-wrapper"
            ref={containerRef}
            dangerouslySetInnerHTML={{ __html: svg }}
            style={{ width: '100%', overflowX: 'auto', display: 'flex', justifyContent: 'center' }}
        />
    );
};

export default MermaidDiagram;
