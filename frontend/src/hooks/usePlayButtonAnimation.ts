import { useEffect } from "react";
import {
  useMotionValue,
  useSpring,
  useTransform,
} from "motion/react";

export function usePlayButtonAnimation() {
  const pointerDown = useMotionValue(0);
  const isUp = useTransform(
    () => (pointerDown.get() > 0.5 ? 1 : 0) as number,
  );

  const blurBase = useMotionValue(0);
  const blur = useSpring(blurBase, { damping: 30, stiffness: 200 });
  const specularOpacity = useMotionValue(0.6);
  const specularSaturation = useMotionValue(12);
  const refractionBase = useMotionValue(1.1);

  const pressMultiplier = useTransform(
    isUp as any,
    [0, 1],
    [0.4, 0.9],
  );

  const scaleRatio = useSpring(
    useTransform(
      [pressMultiplier, refractionBase],
      ([m, base]) => (Number(m) || 0) * (Number(base) || 0),
    ),
  );

  const scaleSpring = useSpring(
    useTransform(isUp as any, [0, 1], [1, 0.95]),
    { damping: 80, stiffness: 2000 },
  );

  const backgroundOpacity = useMotionValue(0.7);

  const backgroundColor = useTransform(
    backgroundOpacity,
    (op) => `rgba(40, 39, 39, ${op})`,
  );

  useEffect(() => {
    const timer = setTimeout(() => {
      blurBase.set(3);
    }, 500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    pointerDown,
    blur,
    scaleRatio,
    specularOpacity,
    specularSaturation,
    scaleSpring,
    backgroundColor,
  };
}
