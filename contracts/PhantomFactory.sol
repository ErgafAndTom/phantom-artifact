// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./PhantomSink.sol";

/// @title PhantomFactory — фабрика ничейных аккаунтов через CREATE2
/// @notice Деплоит PhantomSink по детерминистическому адресу.
///         Адрес можно вычислить ДО деплоя (counterfactual existence).
/// @dev Каждый salt → уникальный адрес. Один salt → один деплой.
contract PhantomFactory {
    
    event PhantomDeployed(bytes32 indexed salt, address indexed phantom);
    
    /// @notice Реестр: salt → задеплоенный адрес
    mapping(bytes32 => address) public registry;
    
    /// @notice Счётчик задеплоенных фантомов
    uint256 public totalDeployed;
    
    /// @notice Деплоит PhantomSink по заданному salt
    /// @param salt Любые 32 байта — определяют итоговый адрес
    /// @return addr Адрес задеплоенного контракта
    function deploy(bytes32 salt) external returns (address addr) {
        require(registry[salt] == address(0), "PhantomFactory: salt already used");
        
        PhantomSink phantom = new PhantomSink{salt: salt}();
        addr = address(phantom);
        registry[salt] = addr;
        totalDeployed++;
        
        emit PhantomDeployed(salt, addr);
    }
    
    /// @notice Вычисляет адрес БЕЗ деплоя (counterfactual)
    /// @param salt Те же 32 байта что будут использованы при deploy()
    /// @return addr Адрес где БУДЕТ контракт после деплоя
    function computeAddress(bytes32 salt) external view returns (address addr) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(type(PhantomSink).creationCode)
            )
        );
        addr = address(uint160(uint256(hash)));
    }
    
    /// @notice Проверяет, задеплоен ли фантом с данным salt
    function isDeployed(bytes32 salt) external view returns (bool) {
        return registry[salt] != address(0);
    }
    
    /// @notice Генерирует salt из произвольной строки
    /// @dev Удобство: deploy(saltFrom("my-project-treasury"))
    function saltFrom(string memory label) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("phantom-v1:", label));
    }
}
