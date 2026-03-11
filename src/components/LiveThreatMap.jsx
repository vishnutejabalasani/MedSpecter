import React, { useRef, useEffect, useState, useCallback } from 'react';
import Globe from 'react-globe.gl';

export default function LiveThreatMap({ alerts }) {
    const globeEl = useRef();
    const containerRef = useRef();
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
    const [arcsData, setArcsData] = useState([]);
    const [ringsData, setRingsData] = useState([]);
    const [labelsData, setLabelsData] = useState([]);

    // Hardcoded server location (Hyderabad, India)
    const serverLocation = { lat: 17.3850, lng: 78.4867, label: 'HYDERABAD DATACENTER' };

    // Measure container dimensions for the Globe canvas
    useEffect(() => {
        const el = containerRef.current;
        if (!el) return;
        const ro = new ResizeObserver(entries => {
            for (const entry of entries) {
                const { width, height } = entry.contentRect;
                setDimensions({ width, height });
            }
        });
        ro.observe(el);
        // Also measure immediately
        setDimensions({ width: el.clientWidth, height: el.clientHeight });
        return () => ro.disconnect();
    }, []);

    useEffect(() => {
        // Configure cinematic globe controls
        if (globeEl.current) {
            // Center the globe over India on load
            globeEl.current.pointOfView({ lat: 20, lng: 80, altitude: 2.2 });
            globeEl.current.controls().autoRotate = true;
            globeEl.current.controls().autoRotateSpeed = 1.2;

            // Add a subtle blue ambient light to make the dark earth look more cyber
            const scene = globeEl.current.scene();
            const ambientLight = scene.children.find(obj3d => obj3d.type === 'AmbientLight');
            if (ambientLight) {
                ambientLight.color.setHex(0x224488);
                ambientLight.intensity = 1.5;
            }
        }
    }, [dimensions]);

    useEffect(() => {
        // Process incoming alerts
        if (alerts && alerts.length > 0) {
            const latestAlertsWithGeo = alerts
                .filter(alert => alert.lat && alert.lng)
                .slice(0, 8); // Keep the last 8 active to prevent clutter

            const arcs = [];
            const rings = [];
            const labels = [];

            // Add server destination ring and label
            rings.push({
                lat: serverLocation.lat,
                lng: serverLocation.lng,
                color: '#10b981',
                maxR: 12,
                propagationSpeed: 2,
                repeatPeriod: 1500
            });

            labels.push({
                lat: serverLocation.lat,
                lng: serverLocation.lng,
                text: serverLocation.label,
                color: '#10b981',
                size: 1.5
            });

            latestAlertsWithGeo.forEach(alert => {
                const colors = getSeverityColor(alert.type);
                const isCritical = alert.type === 'CRITICAL';

                arcs.push({
                    startLat: alert.lat,
                    startLng: alert.lng,
                    endLat: serverLocation.lat,
                    endLng: serverLocation.lng,
                    color: colors,
                    alt: isCritical ? 0.35 : 0.2
                });

                // Attack origin ring ripple
                rings.push({
                    lat: alert.lat,
                    lng: alert.lng,
                    color: colors[0],
                    maxR: isCritical ? 15 : 8,
                    propagationSpeed: isCritical ? 4 : 2,
                    repeatPeriod: isCritical ? 700 : 1200
                });

                // Attack origin label
                labels.push({
                    lat: alert.lat,
                    lng: alert.lng,
                    text: `${alert.country.toUpperCase()} [${alert.type.toUpperCase()}]`,
                    color: colors[1], // Use the brighter gradient stop for text
                    size: isCritical ? 1.5 : 1.0
                });
            });

            setArcsData(arcs);
            setRingsData(rings);
            setLabelsData(labels);
        }
    }, [alerts]);

    const getSeverityColor = (severity) => {
        // Gradients for glowing arcs [Base Color, Highlight Color]
        switch (severity) {
            case 'CRITICAL': return ['#ef4444', '#ff8888']; // Intense Red
            case 'HIGH': return ['#f59e0b', '#ffcc55'];     // Neon Orange
            case 'MEDIUM': return ['#3b82f6', '#88ccff'];   // Cyber Blue
            default: return ['#10b981', '#77ffaa'];         // Hacker Green
        }
    };

    return (
        <div ref={containerRef} style={{ width: '100%', height: '100%', borderRadius: '12px', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.05)', position: 'relative', background: '#050510' }}>
            <div style={{
                position: 'absolute', top: 20, left: 20, zIndex: 10,
                background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(12px)',
                padding: '12px 24px', borderRadius: '30px', border: '1px solid rgba(239, 68, 68, 0.5)',
                fontSize: '0.9rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '12px',
                boxShadow: '0 0 25px rgba(239, 68, 68, 0.25)'
            }}>
                <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#ff3333', boxShadow: '0 0 12px #ff3333', animation: 'pulsate 1.2s infinite ease-in-out' }}></div>
                <strong style={{ letterSpacing: '3px', color: '#ffaaaa', textShadow: '0 0 8px rgba(255,100,100,0.5)' }}>DEFCON-2 GEO-TRACKING ACTIVE</strong>
            </div>

            {dimensions.width > 0 && dimensions.height > 0 && <Globe
                ref={globeEl}
                width={dimensions.width}
                height={dimensions.height}
                // High-res futuristic textures
                globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
                backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"

                // Arcs (Lasers)
                arcsData={arcsData}
                arcStartLat={d => d.startLat}
                arcStartLng={d => d.startLng}
                arcEndLat={d => d.endLat}
                arcEndLng={d => d.endLng}
                arcColor={d => d.color}
                arcAltitude={d => d.alt}
                arcDashLength={0.4}
                arcDashGap={1}
                arcDashInitialGap={() => Math.random()}
                arcDashAnimateTime={2000}
                arcsTransitionDuration={0}
                arcStroke={0.8}

                // Rings (Ripples)
                ringsData={ringsData}
                ringColor={d => t => {
                    // Fade out ring as it expands
                    const color = d.color.replace('#', '');
                    const r = parseInt(color.substring(0, 2), 16);
                    const g = parseInt(color.substring(2, 4), 16);
                    const b = parseInt(color.substring(4, 6), 16);
                    return `rgba(${r},${g},${b},${1 - t})`;
                }}
                ringMaxRadius={d => d.maxR}
                ringPropagationSpeed={d => d.propagationSpeed}
                ringRepeatPeriod={d => d.repeatPeriod}

                // Labels (Text floating above map)
                labelsData={labelsData}
                labelLat={d => d.lat}
                labelLng={d => d.lng}
                labelText={d => d.text}
                labelSize={d => d.size}
                labelDotRadius={0.4}
                labelColor={d => d.color}
                labelResolution={2}
                labelAltitude={0.01}

                backgroundColor="rgba(0,0,0,0)"
            />}
            <style>{`
                @keyframes pulsate {
                    0% { transform: scale(0.95); opacity: 0.8; }
                    50% { transform: scale(1.3); opacity: 1; box-shadow: 0 0 20px #ff3333; }
                    100% { transform: scale(0.95); opacity: 0.8; }
                }
            `}</style>
        </div>
    );
}
