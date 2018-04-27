# Android - Android Stack

At the lowest level, Android is based on a variation of the **Linux Kernel**,
taking care of underlying functionalities such as threading and low-level
memory management.

On top of the kernel, the **Hardware Abstraction Layer (HAL)** defines a
standard interface for interacting with built-in hardware components, providing
access to device hardware capabilities to the higher-level Java API framework.
The HAL consists of multiple library modules, each of which implements an
interface for a specific type of hardware component, such as the camera or
bluetooth module. When a framework API makes a call to access device hardware,
the Android system loads the library module for that hardware component.



Android applications don't have direct access to hardware resources, and each
application runs in its own sandbox.
This allows precise control over resources and applications: for instance, a
crashing application doesn't affect other applications running on the device.
At the same time, the Android runtime controls the maximum number of system
resources allocated to apps, preventing any app from monopolizing too
many resources.
