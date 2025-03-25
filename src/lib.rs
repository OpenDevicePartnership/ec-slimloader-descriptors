//! Descriptors for use with the ec-slimloader bootloader. Can be leveraged by an OTA update process such as CFU to enable firmware update.
//!
//! ## theory of operation
//!
//! The descriptors are built into two pieces: a descriptor header (BootableRegionDescriptorHeader) and a list of application image descriptors (AppImageDescriptor). Together, these describe the layout of a bootable region. These can be managed via a manager struct (BootableRegionDescriptors).
//!
//! The expected boot flow would be as follows:
//!
//! 1. Bootloader reads BootableRegionDescriptorHeader from chip-specific offset
//! 2. Descriptor header is validated and CRC is checked. App image descriptors are also validated for integrity.
//! 3. Bootloader loads the active app image descriptor per the active slot indicated in the header
//! 4. Depending on image flags, bootloader may perform a CRC integrity check over the app image in place
//! 5. Depending on image flags, the bootloader may copy the validated image from stored_image_address to execution_image_address
//! 6. If everything has been validated and copied, the bootloader will set the VTOR and main stack pointer, then branch to the reset vector

#![no_std]

use core::mem::size_of;

use bytemuck::{Pod, Zeroable};
use constmuck::bytes_of;
/// re-export for matching software CRC32 checksum
pub use crc::{Crc, Digest, CRC_32_CKSUM};

mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}
/// Descriptor Version pulled in -- corresponds to crate package version
pub const DESCRIPTOR_VERSION: u32 = version::CRATE_VERSION;

/// Just the major field of the descriptor version
pub const DESCRIPTOR_VERSION_MAJOR: u32 = (DESCRIPTOR_VERSION >> 24) & 0xFF;

/// Just the minor field of the descriptor version
pub const DESCRIPTOR_VERSION_MINOR: u32 = (DESCRIPTOR_VERSION >> 8) & 0xFFFF;

/// Just the patch field of the descriptor version
pub const DESCRIPTOR_VERSION_PATCH: u32 = DESCRIPTOR_VERSION & 0xFF;

/// Magic number for finding or aligning bootable region descriptors header
pub const BOOT_REGION_DESCRIPTOR_SIGNATURE: u32 = 0x2222_2222;

/// Size of the DESCRIPTOR_VERSION iteration of the bootable region descriptors header
pub const BOOT_REGION_DESCRIPTOR_SIZE: usize = size_of::<BootableRegionDescriptorHeader>();

/// App Image Flags: No flags set
pub const APP_IMAGE_FLAG_NONE: u32 = 0x0000_0000;

/// App Image Flags: Perform a memory write from stored_address to execution_address in the app image descriptor before executing
pub const APP_IMAGE_FLAG_COPY_TO_EXECUTION_ADDRESS: u32 = 0x0000_0001;

/// App Image Flags: Skip CRC32 checksum integrity check on app image corresponding to app image descriptor
pub const APP_IMAGE_FLAG_SKIP_IMAGE_CRC_CHECK: u32 = 0x0000_0002;

/// Size of the DESCRIPTOR_VERSION of the bootable region app image descriptor
pub const APP_IMAGE_DESCRIPTOR_SIZE: usize = size_of::<AppImageDescriptor>();

/// The actual descriptor region header
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
pub struct BootableRegionDescriptorHeader {
    /// BOOT_REGION_DESCRIPTOR_SIGNATURE
    pub signature: u32,

    /// DESCRIPTOR_VERSION in the format h'MM_mmmm_pp
    pub descriptor_version: u32,

    /// BOOT_REGION_DESCRIPTOR_SIZE
    pub descriptor_header_size_bytes: u32,

    /// APP_IMAGE_DESCRIPTOR_SIZE
    pub app_descriptor_size_bytes: u32,

    /// Readable address where AppImageDescriptor\[num_active_slots\] is placed
    pub app_descriptor_base_address: u32,

    /// The number of AppImageDescriptor's in the bootable descriptor region
    pub num_app_slots: u32,

    /// Corresponds to which AppImageDescriptor should be booted
    pub active_app_slot: u32,

    /// CRC32 checksum of above parameters
    pub header_crc: u32,
}

/// The App Image Descriptor for describing layout and usage of corresponding app image
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
pub struct AppImageDescriptor {
    /// DESCRIPTOR_VERSION in the format h'MM_mmmm_pp
    pub descriptor_version: u32,

    /// Corresponds to index in AppImageDescriptor\[BootableRegionDescriptorHeader::num_app_slots\]
    pub app_slot_number: u32,

    /// Application version for handling recovery and roll forward or back behaviors
    pub app_version: u32,

    /// Security version corresponding to this application image for roll-back attack protection enablement
    pub security_version: u32,

    /// App image behavior flags
    pub flags: u32,

    /// Where the full, contiguous app image is stored
    pub stored_address: u32,

    /// The size of the app image stored at stored_address
    pub image_size_bytes: u32,

    /// The address where the CRC32 checksum over stored_address through stored_address + image_size_bytes is kept
    pub stored_crc_address: u32,

    /// how much memory to move from stored_address to execution_address before performing app load from bootloader
    pub execution_copy_size_bytes: u32,

    /// where to begin execution once the app image is validated and loaded
    pub execution_address: u32,

    /// CRC32 checksum over the above parameters
    pub descriptor_crc: u32,
}

/// Descriptor parsing error conditions
#[derive(Copy, Clone, Debug)]
pub enum ParseError {
    /// Descriptor region header does not start with BOOT_REGION_DESCRIPTOR_SIGNATURE
    InvalidSignature,

    /// Descriptor region header CRC32 checksum is invalid or header is corrupted
    InvalidHeaderCrc {
        /// what CRC32 was found at provided header offset
        found: u32,
        /// what CRC32 checksum should have been based on current contents
        expected: u32,
    },

    /// App image descriptor CRC32 checksum is invalid or image descriptor is corrupted
    InvalidAppCrc {
        /// where the app image descriptor was searched for
        address: *const u32,
        /// what was found at the CRC32 offset in the image descriptor (descriptor_crc parameter)
        found: u32,
        /// what was expected to be computed based on current contents of the image descriptor
        expected: u32,
    },

    /// Active app slot is beyond the range of acceptable values based on num_app_slots
    InvalidAppSlot,

    /// num_app_slots is 0 or otherwise uninterpretable
    InvalidSlotCount,
}

/// Manager struct to make loading and writing botable region header and app image descriptors easier
pub struct BootableRegionDescriptors {
    _base_address: *const u8,
    header: BootableRegionDescriptorHeader,
}

impl BootableRegionDescriptors {
    /// Attempt to load from address the bootable region descriptors, header and app images
    pub fn from_address(address: *const u32) -> Result<BootableRegionDescriptors, ParseError> {
        // cache off basic data used later
        let this = Self {
            _base_address: address as *const u8,
            header: BootableRegionDescriptorHeader::from_address(address)?,
        };

        // loop over and validate all app slot descriptors, pass up failures if they exist
        for i in 0..this.header.num_app_slots {
            let _app_image_descriptor =
                AppImageDescriptor::from_region(this.header.app_descriptor_base_address as *const u32, i)?;
        }

        // only allow construction of bootable region descriptors from memory if all slots are valid
        Ok(this)
    }

    /// Once a valid descriptor set is read, request the currently active marked App Image Descriptor
    pub fn get_active_slot(&self) -> AppImageDescriptor {
        // can't fail as BootableRegionDescriptors only constructs if all app descriptors are valid
        AppImageDescriptor::from_region(
            self.header.app_descriptor_base_address as *const u32,
            self.header.active_app_slot,
        )
        .unwrap()
    }

    /// Get descriptor for a specific app slot
    pub fn get_app_at_slot(&self, app_slot: u32) -> Result<AppImageDescriptor, ParseError> {
        if app_slot >= self.header.num_app_slots {
            return Err(ParseError::InvalidAppSlot);
        }

        // can't fail as BootableRegionDescriptors only constructs if all app descriptors are valid
        AppImageDescriptor::from_region(self.header.app_descriptor_base_address as *const u32, app_slot)
    }
}

impl BootableRegionDescriptorHeader {
    /// Attempt to load a bootable region descriptor header from provided address
    pub fn from_address(address: *const u32) -> Result<BootableRegionDescriptorHeader, ParseError> {
        let unvalidated = unsafe { *(address as *const BootableRegionDescriptorHeader) };

        if unvalidated.signature != BOOT_REGION_DESCRIPTOR_SIGNATURE {
            Err(ParseError::InvalidSignature)
        } else if !unvalidated.is_crc_valid() {
            Err(ParseError::InvalidHeaderCrc {
                found: unvalidated.header_crc,
                expected: unvalidated.compute_crc(),
            })
        } else if unvalidated.num_app_slots < 1 {
            Err(ParseError::InvalidSlotCount)
        } else if unvalidated.active_app_slot >= unvalidated.num_app_slots {
            Err(ParseError::InvalidAppSlot)
        } else {
            Ok(unvalidated)
        }
    }

    /// Generate at compile time a descriptor region header. Useful for initialization and explicit linker placement for debug scenarios
    pub const fn new(
        app_slot_count: u32,
        active_app_slot: u32,
        app_descriptor_address: u32,
    ) -> BootableRegionDescriptorHeader {
        let mut this = BootableRegionDescriptorHeader {
            signature: BOOT_REGION_DESCRIPTOR_SIGNATURE,
            descriptor_version: DESCRIPTOR_VERSION,
            descriptor_header_size_bytes: BOOT_REGION_DESCRIPTOR_SIZE as u32,
            app_descriptor_size_bytes: APP_IMAGE_DESCRIPTOR_SIZE as u32,
            app_descriptor_base_address: app_descriptor_address,
            num_app_slots: app_slot_count,
            active_app_slot,
            header_crc: 0,
        };

        this.header_crc = this.compute_crc();

        this
    }

    /// Return this struct's contents as a slice
    pub const fn as_bytes(&self) -> &[u8] {
        bytes_of(self)
    }

    /// Return the CRC32 checksum over the current contents of this struct
    pub const fn compute_crc(&self) -> u32 {
        let full_bytes = bytes_of(self);

        // TODO - figure out a way to do a const slice semantically cleanly
        // NOTE - as a const fn it's entirely possible this will not be allocated at all in a real program
        let mut without_crc = [0u8; BOOT_REGION_DESCRIPTOR_SIZE - size_of::<u32>()];
        let mut i = 0;
        while i < without_crc.len() {
            without_crc[i] = full_bytes[i];
            i += 1;
        }

        Crc::<u32>::new(&CRC_32_CKSUM).checksum(&without_crc)
    }

    /// Check if the header_crc value matches the current computed CRC32 checksum
    pub const fn is_crc_valid(&self) -> bool {
        self.header_crc == self.compute_crc()
    }
}

impl AppImageDescriptor {
    /// Attempt to read app_slot AppImageDescriptor from app_descriptors_address_start
    pub fn from_region(
        app_descriptors_address_start: *const u32,
        app_slot: u32,
    ) -> Result<AppImageDescriptor, ParseError> {
        AppImageDescriptor::from_address(unsafe {
            (app_descriptors_address_start as *const u8).add((app_slot as usize) * APP_IMAGE_DESCRIPTOR_SIZE)
                as *const u32
        })
    }

    /// Generate a non-copied (XIP: execute in place) app image descriptor with the given parameters
    pub const fn new_execute_in_place_image(
        slot: u32,
        app_version: u32,
        security_version: u32,
        flags: u32,
        stored_address: u32,
        image_size_bytes: u32,
        stored_crc_address: u32,
    ) -> AppImageDescriptor {
        let mut app_image_descriptor = Self {
            descriptor_version: DESCRIPTOR_VERSION,
            app_slot_number: slot,
            app_version,
            security_version,
            flags,
            stored_address,
            image_size_bytes,
            stored_crc_address,
            execution_address: stored_address,
            execution_copy_size_bytes: 0,
            descriptor_crc: 0,
        };

        app_image_descriptor.descriptor_crc = app_image_descriptor.compute_crc();

        app_image_descriptor
    }

    #[allow(clippy::too_many_arguments)]
    /// Generate a copied to RAM app image descriptor with given parameters
    pub const fn new_ram_image(
        slot: u32,
        app_version: u32,
        security_version: u32,
        flags: u32,
        flash_address: u32,
        image_size_bytes: u32,
        ram_address: u32,
        stored_crc_address: u32,
    ) -> Self {
        let mut app_image_descriptor = Self {
            descriptor_version: DESCRIPTOR_VERSION,
            app_slot_number: slot,
            app_version,
            security_version,
            flags: flags | APP_IMAGE_FLAG_COPY_TO_EXECUTION_ADDRESS,
            stored_address: flash_address,
            image_size_bytes,
            stored_crc_address,
            execution_address: ram_address,
            execution_copy_size_bytes: image_size_bytes,
            descriptor_crc: 0,
        };

        app_image_descriptor.descriptor_crc = app_image_descriptor.compute_crc();

        app_image_descriptor
    }

    /// Attempt to interpret address memory contents as an AppImageDescriptor
    pub fn from_address(address: *const u32) -> Result<AppImageDescriptor, ParseError> {
        let unvalidated = unsafe { *(address as *const AppImageDescriptor) };

        if !unvalidated.is_crc_valid() {
            Err(ParseError::InvalidAppCrc {
                address,
                found: unvalidated.descriptor_crc,
                expected: unvalidated.compute_crc(),
            })
        } else {
            Ok(unvalidated)
        }
    }

    /// Return this structure as a slice
    pub const fn as_bytes(&self) -> &[u8] {
        bytes_of(self)
    }

    /// Compute the CRC32 checksum of this structures current contents
    pub const fn compute_crc(&self) -> u32 {
        let full_bytes = bytes_of(self);

        // TODO - figure out a way to do a const slice semantically cleanly
        // NOTE - as a const fn it's entirely possible this will not be allocated at all in a real program
        let mut without_crc = [0u8; APP_IMAGE_DESCRIPTOR_SIZE - size_of::<u32>()];
        let mut i = 0;
        while i < without_crc.len() {
            without_crc[i] = full_bytes[i];
            i += 1;
        }

        Crc::<u32>::new(&CRC_32_CKSUM).checksum(&without_crc)
    }

    /// Check this structure's stored descriptor_crc against computed CRC32 checksum of its current contents
    pub const fn is_crc_valid(&self) -> bool {
        self.descriptor_crc == self.compute_crc()
    }
}

#[cfg(test)]
mod unit_tests {

    #[test]
    fn test_ram_descriptor_gen() {
        use super::*;

        let app_image_descriptor = AppImageDescriptor::new_ram_image(
            0,
            0,
            0,
            APP_IMAGE_FLAG_NONE | APP_IMAGE_FLAG_SKIP_IMAGE_CRC_CHECK,
            0,
            0,
            0,
            0,
        );

        assert_ne!(app_image_descriptor.flags & APP_IMAGE_FLAG_COPY_TO_EXECUTION_ADDRESS, 0);
        let embedded_crc = app_image_descriptor.descriptor_crc;
        let computed_crc = app_image_descriptor.compute_crc();
        assert_eq!(embedded_crc, computed_crc);
    }

    #[test]
    fn bootable_region_descriptors_init() {}

    #[test]
    fn bootable_region_descriptors_load() {}

    #[test]
    fn bootable_region_descriptors_catch_garbage() {}
}
