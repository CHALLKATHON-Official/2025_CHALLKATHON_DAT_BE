import React, { useEffect } from "react";
import * as THREE from "three";
import { Canvas } from "@react-three/fiber";
import { useSprings, a } from "@react-spring/three";

const number = 30;
const colors = ["#4285F4", "#EA4335", "#FBBC05", "#34A853"];

const random = (i) => {
  const r = Math.random();
  return {
    position: [100 - Math.random() * 200, 100 - Math.random() * 200, i * 1.5],
    color: colors[Math.round(Math.random() * (colors.length - 1))],
    scale: [1 + r * 14, 1 + r * 14, 1],
    rotation: [0, 0, THREE.MathUtils.degToRad(Math.round(Math.random()) * 45)],
  };
};

const data = new Array(number).fill(null).map(() => {
  return {
    color: colors[Math.round(Math.random() * (colors.length - 1))],
    args: [0.1 + Math.random() * 9, 0.1 + Math.random() * 9, 10],
  };
});

function Content() {
  const [springs, api] = useSprings(number, (i) => ({
    from: random(i),
    ...random(i),
    config: { mass: 20, tension: 150, friction: 50 },
  }));

  useEffect(
    () =>
      void setInterval(
        () => api.start((i) => ({ ...random(i), delay: i * 40 })),
        3000
      ),
    []
  );

  return (
    <>
      {data.map((d, index) => (
        <a.mesh key={index} {...springs[index]} castShadow receiveShadow>
          <boxGeometry attach="geometry" args={d.args} />
          <a.meshStandardMaterial
            attach="material"
            color={springs[index].color}
            roughness={0.2} // 매끈하게 = 더 빛을 반사함
            metalness={0.1} // 메탈 느낌 줄이기
          />
        </a.mesh>
      ))}
    </>
  );
}

function Lights() {
  return (
    <group>
      <pointLight intensity={0.3} />
      <ambientLight intensity={3} /> // 주변광 더 밝게
      <spotLight
        castShadow
        intensity={1.5} // 스포트라이트 더 밝게
        angle={Math.PI / 6}
        position={[150, 150, 250]}
        penumbra={1}
        shadow-mapSize-width={2048}
        shadow-mapSize-height={2048}
      />
    </group>
  );
}

export default function AwesomeBackground() {
  return (
    <div className="awesome-bg">
      <Canvas linear flat shadows camera={{ position: [0, 0, 100], fov: 100 }}>
        <Lights />
        <Content />
      </Canvas>
    </div>
  );
}
