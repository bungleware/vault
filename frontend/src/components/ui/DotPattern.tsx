'use client'

import { cn } from '@/lib/utils'

interface DotPatternProps {
    width?: number
    height?: number
    className?: string
}

const DotPattern = ({ width = 16, height = 16, className }: DotPatternProps) => {
    return (
        <svg className={cn('absolute inset-0 h-full w-full [mask-image:radial-gradient(100%_100%_at_top_center,white,transparent)]', className)} aria-hidden="true">
            <defs>
                <pattern id="dotPattern" width={width} height={height} patternUnits="userSpaceOnUse">
                    <circle cx={width * 0.5} cy={height * 0.5} r="1" className="fill-white/10" />
                </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#dotPattern)" />
        </svg>
    )
}

export default DotPattern
