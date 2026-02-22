import { forwardRef, useImperativeHandle } from "react";
import { motion, useAnimation, type Variants, type Easing } from "motion/react";

export interface AnimatedIconHandle {
  play: () => void;
}

interface AnimatedIconProps {
  className?: string;
  triangleWidth?: number;
  triangleHeight?: number;
  gap?: number;
}

const trianglePathRight = "M 0 0 L 10 7 L 0 14 Z";
const trianglePathLeft = "M 10 0 L 0 7 L 10 14 Z";

const ANIMATION_DURATION = 0.6;
const ANIMATION_EASE: Easing = [0.2, 0.8, 0.2, 1.1];
const LEFT_POS = 2;
const RIGHT_POS = 14.5;
const EXIT_DISTANCE = 10;
const MIN_SCALE = 0;
const MAX_SCALE = 1;
const COMPONENT_SCALE = 1.0;

export const AnimatedSkipForwardIcon = forwardRef<
  AnimatedIconHandle,
  AnimatedIconProps
>(({ className }, ref) => {
  const controls = useAnimation();

  useImperativeHandle(ref, () => ({
    play: () => {
      controls.stop();
      controls.set("initial");
      controls.start("animate");
    },
  }));

  const variants: Variants = {
    initial: (custom: number) => ({
      x: custom === 2 ? RIGHT_POS : custom === 1 ? LEFT_POS : -12,
      scale: custom === 0 ? MIN_SCALE : MAX_SCALE,
      opacity: custom === 0 ? 0 : 1,
      transition: { duration: 0 },
    }),
    animate: (custom: number) => {
      if (custom === 2)
        return {
          x: RIGHT_POS + EXIT_DISTANCE,
          scale: MIN_SCALE,
          opacity: 0,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      if (custom === 1)
        return {
          x: RIGHT_POS,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      if (custom === 0)
        return {
          x: LEFT_POS,
          opacity: 1,
          scale: MAX_SCALE,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      return {};
    },
  };

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 26 24"
      fill="currentColor"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={{ overflow: "visible", transform: `scale(${COMPONENT_SCALE})` }}
    >
      <motion.path
        d={trianglePathRight}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={0}
        style={{ y: 5 }}
      />
      <motion.path
        d={trianglePathRight}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={1}
        style={{ y: 5 }}
      />
      <motion.path
        d={trianglePathRight}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={2}
        style={{ y: 5 }}
      />
    </svg>
  );
});

export const AnimatedSkipBackIcon = forwardRef<
  AnimatedIconHandle,
  AnimatedIconProps
>(({ className }, ref) => {
  const controls = useAnimation();

  useImperativeHandle(ref, () => ({
    play: () => {
      controls.stop();
      controls.set("initial");
      controls.start("animate");
    },
  }));

  const variants: Variants = {
    initial: (custom: number) => ({
      x:
        custom === 2
          ? LEFT_POS
          : custom === 1
            ? RIGHT_POS
            : RIGHT_POS + EXIT_DISTANCE,
      scale: custom === 0 ? MIN_SCALE : MAX_SCALE,
      opacity: custom === 0 ? 0 : 1,
      transition: { duration: 0 },
    }),
    animate: (custom: number) => {
      if (custom === 2)
        return {
          x: LEFT_POS - EXIT_DISTANCE,
          scale: MIN_SCALE,
          opacity: 0,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      if (custom === 1)
        return {
          x: LEFT_POS,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      if (custom === 0)
        return {
          x: RIGHT_POS,
          opacity: 1,
          scale: MAX_SCALE,
          transition: { duration: ANIMATION_DURATION, ease: ANIMATION_EASE },
        };
      return {};
    },
  };

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 26 24"
      fill="currentColor"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={{ overflow: "visible", transform: `scale(${COMPONENT_SCALE})` }}
    >
      <motion.path
        d={trianglePathLeft}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={0}
        style={{ y: 5 }}
      />
      <motion.path
        d={trianglePathLeft}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={1}
        style={{ y: 5 }}
      />
      <motion.path
        d={trianglePathLeft}
        initial="initial"
        animate={controls}
        variants={variants}
        custom={2}
        style={{ y: 5 }}
      />
    </svg>
  );
});
